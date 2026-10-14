"""Regression tests for praise.runtime and the praise CLI.

Covers the consumer-visible invariants of the control layer: scoped init,
state transitions, two-repro distinctness, source-candidate gating without
runtime proof, evidence escape/change detection, different-family final
decisions, unsafe fix acceptance, exact URL boundaries, redirect refusal, and
shared request budgets. Uses only the standard library (unittest).
"""

from __future__ import annotations

import contextlib
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.server
import io
import json
import os
import sys
import sqlite3
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from praise import cli, policy, runtime

# Synthetic identity vectors; these tests do not invoke model providers.
DS_PRO = "opencode-go/deepseek-v4-pro:high"
DS_FLASH = "opencode-go/deepseek-v4.1-flash:high"
GLM = "opencode-go/glm-5.3-flash:high"
GROK = "opencode-go/grok-4.7:high"
GPT = "openai-codex/gpt-daybreak-blue-latest:high"
MIMO = "opencode-go/mimo-v2.6-flash:high"


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.hits.append(self.path)
        if self.path == "/api/v1/redirect":
            self.send_response(302)
            self.send_header("Location", "/outside")
            self.end_headers()
            return
        if self.path.startswith("/api/v1/secrets"):
            body = json.dumps({
                "witness": "synthetic record",
                "token": "response-only-control",
                "nested": {"password": "nested-control"},
                "echo": self.headers.get("Authorization"),
                "path": self.path,
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/api/v1/large":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"x" * (runtime.MAX_RESPONSE_BYTES + 17))
            return
        if self.path == "/api/v1/ok":
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, *args):  # silence request logging
        pass


class RuntimeTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def _source_dir(self):
        d = os.path.join(self.root, "source")
        os.makedirs(d, exist_ok=True)
        return d

    def _write_evidence(self, engagement, ref, content: bytes):
        path = os.path.join(engagement, "evidence", ref)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(content)
        return path

    def _init_source(self, name="eng", **kw):
        eng = os.path.join(self.root, name)
        return runtime.init_engagement(
            eng, program="p", basis="b", assets=[self._source_dir()], mode="source", **kw
        ), eng

    def _new_source_candidate(self, eng, evidence="e1.json", producer=DS_PRO, **extra):
        self._write_evidence(eng, evidence, b"evidence-v1")
        finding = {
            "producer_model": producer,
            "evidence": [evidence],
            "source_ref": "src/a.py:10",
            "sink_ref": "src/b.py:20",
        }
        finding.update(extra)
        return runtime.create_candidate(eng, finding)


class ModelFamilyTests(RuntimeTestBase):
    def test_known_families(self):
        self.assertEqual(runtime.model_family(DS_PRO), "deepseek")
        self.assertEqual(runtime.model_family(DS_FLASH), "deepseek")
        self.assertEqual(runtime.model_family(GLM), "glm")
        self.assertEqual(runtime.model_family(GROK), "grok")
        self.assertEqual(runtime.model_family(GPT), "gpt")
        self.assertEqual(runtime.model_family(MIMO), "mimo")

    def test_unknown_family_is_none(self):
        self.assertIsNone(runtime.model_family("some-obscure-model"))
        self.assertIsNone(runtime.model_family(""))
        self.assertIsNone(runtime.model_family(None))


class InitScopeTests(RuntimeTestBase):
    def test_init_roundtrip_and_source_roots(self):
        scope, eng = self._init_source()
        self.assertEqual(scope["mode"], "source")
        self.assertEqual(scope["url_assets"], [])
        self.assertEqual(len(scope["source_roots"]), 1)
        loaded = runtime.load_scope(eng)
        self.assertEqual(loaded["program"], "p")
        self.assertEqual(loaded["authorization_basis"], "b")
        self.assertEqual(loaded["source_roots"], scope["source_roots"])

    def test_init_requires_authorization(self):
        with self.assertRaises(runtime.PraiseError):
            runtime.init_engagement(
                os.path.join(self.root, "e"), program="p", basis="", assets=[self._source_dir()]
            )

    def test_init_requires_assets(self):
        with self.assertRaises(runtime.PraiseError):
            runtime.init_engagement(
                os.path.join(self.root, "e"), program="p", basis="b", assets=[], mode="source"
            )

    def test_init_requires_absolute_directory_asset(self):
        with self.assertRaises(runtime.PraiseError):
            runtime.init_engagement(
                os.path.join(self.root, "e"), program="p", basis="b", assets=["relative/dir"], mode="source"
            )

    def test_init_refuses_to_truncate_manual_log(self):
        eng = os.path.join(self.root, "e")
        os.makedirs(eng, exist_ok=True)
        with open(os.path.join(eng, "agentschat.md"), "w", encoding="utf-8") as fh:
            fh.write("manual pre-existing content\n")
        with self.assertRaises(runtime.PraiseError):
            runtime.init_engagement(eng, program="p", basis="b", assets=[self._source_dir()])

    def test_source_rejects_http_assets(self):
        with self.assertRaises(runtime.PraiseError):
            runtime.init_engagement(
                os.path.join(self.root, "eng"), program="p", basis="b",
                assets=["https://example.invalid"], mode="source",
            )

    def test_invalid_limits_do_not_create_an_engagement(self):
        for field, value in (
            ("max_requests", 1.5), ("max_requests", True),
            ("interval_seconds", float("nan")), ("interval_seconds", float("inf")),
        ):
            with self.subTest(field=field, value=value):
                eng = os.path.join(self.root, "invalid")
                with self.assertRaises(runtime.PraiseError):
                    runtime.init_engagement(eng, program="p", basis="b", assets=[self._source_dir()], **{field: value})
                self.assertFalse(os.path.exists(eng))


class ArtifactTests(RuntimeTestBase):
    def _make_engagement(self):
        return self._init_source()[1]

    def test_hash_and_path(self):
        eng = self._make_engagement()
        self._write_evidence(eng, "a.txt", b"hello")
        art = runtime.artifact(eng, "a.txt")
        self.assertEqual(art["sha256"], _sha256(b"hello"))
        self.assertTrue(os.path.isabs(art["path"]))

    def test_traversal_rejected(self):
        eng = self._make_engagement()
        with self.assertRaises(ValueError):
            runtime.artifact(eng, "../outside.txt")

    def test_absolute_outside_rejected(self):
        eng = self._make_engagement()
        outside = os.path.join(self.root, "outside.txt")
        with open(outside, "w", encoding="utf-8") as fh:
            fh.write("x")
        with self.assertRaises(ValueError):
            runtime.artifact(eng, outside)

    def test_missing_rejected(self):
        eng = self._make_engagement()
        with self.assertRaises(FileNotFoundError):
            runtime.artifact(eng, "nope.txt")

    def test_symlink_escape_rejected(self):
        eng = self._make_engagement()
        outside = os.path.join(self.root, "secret.txt")
        with open(outside, "w", encoding="utf-8") as fh:
            fh.write("secret")
        os.symlink(outside, os.path.join(eng, "evidence", "link.txt"))
        with self.assertRaises(ValueError):
            runtime.artifact(eng, "link.txt")

    def test_change_detected_by_hash(self):
        eng = self._make_engagement()
        self._write_evidence(eng, "a.txt", b"one")
        art1 = runtime.artifact(eng, "a.txt")
        self._write_evidence(eng, "a.txt", b"two")
        art2 = runtime.artifact(eng, "a.txt")
        self.assertNotEqual(art1["sha256"], art2["sha256"])


class CandidateGateTests(RuntimeTestBase):
    def test_source_candidate_gates_without_runtime_proof(self):
        _, eng = self._init_source()
        cand = self._new_source_candidate(eng)
        self.assertEqual(cand["status"], "candidate")
        result = runtime.gate_candidate(eng, cand["id"], "pass", "source/sink proven", MIMO)
        self.assertEqual(result["status"], "gated")

    def test_boundary_invariant_candidate_gates(self):
        _, eng = self._init_source()
        self._write_evidence(eng, "e1.json", b"x")
        cand = runtime.create_candidate(
            eng,
            {
                "producer_model": DS_PRO,
                "evidence": ["e1.json"],
                "boundary_invariant": "tenant_id must scope every query",
            },
        )
        result = runtime.gate_candidate(eng, cand["id"], "pass", "invariant", MIMO)
        self.assertEqual(result["status"], "gated")

    def test_gate_pass_requires_refs(self):
        _, eng = self._init_source()
        self._write_evidence(eng, "e1.json", b"x")
        cand = runtime.create_candidate(
            eng, {"producer_model": DS_PRO, "evidence": ["e1.json"]}
        )
        with self.assertRaises(runtime.PraiseError):
            runtime.gate_candidate(eng, cand["id"], "pass", "no refs", MIMO)

    def test_candidate_requires_producer_model(self):
        _, eng = self._init_source()
        self._write_evidence(eng, "e1.json", b"x")
        with self.assertRaises(runtime.PraiseError):
            runtime.create_candidate(eng, {"evidence": ["e1.json"], "source_ref": "a", "sink_ref": "b"})

    def test_candidate_tool_is_provenance_only(self):
        _, eng = self._init_source()
        self._write_evidence(eng, "e1.json", b"x")
        cand = runtime.create_candidate(
            eng,
            {
                "producer_model": DS_PRO,
                "evidence": ["e1.json"],
                "source_ref": "a",
                "sink_ref": "b",
                "tool": "generic-scanner",
                "tool_version": "9.9",
            },
        )
        self.assertEqual(cand["tool"], "generic-scanner")
        self.assertEqual(cand["producer_model"], DS_PRO)

    def test_gate_hold_and_drop(self):
        _, eng = self._init_source()
        cand = self._new_source_candidate(eng)
        self.assertEqual(
            runtime.gate_candidate(eng, cand["id"], "hold", "park", MIMO)["status"], "held"
        )
        cand2 = self._new_source_candidate(eng, evidence="e2.json")
        self.assertEqual(
            runtime.gate_candidate(eng, cand2["id"], "drop", "no", MIMO)["status"], "rejected"
        )


class ReproductionVerdictTests(RuntimeTestBase):
    def _gated(self):
        _, eng = self._init_source()
        cand = self._new_source_candidate(eng)
        runtime.gate_candidate(eng, cand["id"], "pass", "ok", MIMO)
        return eng, cand["id"]

    def _reproduce(self, eng, cand_id, run, clean, evidence, model=DS_PRO):
        self._write_evidence(eng, evidence, b"proof-" + evidence.encode())
        return runtime.add_reproduction(eng, cand_id, run, clean, evidence, model)

    def test_two_repro_distinctness(self):
        eng, cand_id = self._gated()
        self._reproduce(eng, cand_id, "r1", "clean-A", "p1.json")
        with self.assertRaises(runtime.PraiseError):
            runtime.record_verdict(eng, cand_id, "confirmed", "two distinct needed", GLM, [])
        # Same clean-state id does not count as a second clean reproduction.
        self._reproduce(eng, cand_id, "r2", "clean-A", "p2.json")
        with self.assertRaises(runtime.PraiseError):
            runtime.record_verdict(eng, cand_id, "confirmed", "two distinct needed", GLM, [])
        # A distinct clean-state id completes the requirement.
        self._reproduce(eng, cand_id, "r3", "clean-B", "p3.json")
        result = runtime.record_verdict(eng, cand_id, "confirmed", "reproduced twice", GLM, [])
        self.assertEqual(result["status"], "confirmed")
        self.assertEqual(result["reproduction_count"], 3)
        self.assertEqual(set(result["distinct_clean_states"]), {"clean-A", "clean-B"})

    def test_different_family_required_for_final_decision(self):
        _, eng = self._init_source()
        cand = self._new_source_candidate(eng)
        # Same-family checker cannot reject either.
        with self.assertRaises(runtime.PraiseError):
            runtime.record_verdict(eng, cand["id"], "rejected", "same family", DS_FLASH, [])
        # A different-family checker can.
        result = runtime.record_verdict(eng, cand["id"], "rejected", "different family", GLM, [])
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["checker_family"], "glm")

    def test_unknown_checker_family_fails_closed(self):
        _, eng = self._init_source()
        cand = self._new_source_candidate(eng)
        with self.assertRaises(runtime.PraiseError):
            runtime.record_verdict(eng, cand["id"], "rejected", "x", "mystery-model", [])

    def test_evidence_change_blocks_confirmation(self):
        eng, cand_id = self._gated()
        self._write_evidence(eng, "e1.json", b"tampered-after-gate")
        self._reproduce(eng, cand_id, "r1", "clean-A", "p1.json")
        self._reproduce(eng, cand_id, "r2", "clean-B", "p2.json")
        with self.assertRaises(runtime.PraiseError):
            runtime.record_verdict(eng, cand_id, "confirmed", "changed", GLM, [])

    def test_producer_models_accumulate(self):
        eng, cand_id = self._gated()
        self._reproduce(eng, cand_id, "r1", "clean-A", "p1.json", model=GLM)
        cand = runtime.get_candidate(eng, cand_id)
        self.assertEqual(cand["producer_models"], [DS_PRO, GLM])

    def test_relabeling_one_artifact_is_not_a_second_reproduction(self):
        eng, candidate_id = self._gated()
        self._reproduce(eng, candidate_id, "first", "clean-A", "proof.json")
        with self.assertRaises(runtime.PraiseError):
            runtime.add_reproduction(eng, candidate_id, "second", "clean-B", "proof.json", DS_PRO)
        self._write_evidence(eng, "copied.json", b"proof-proof.json")
        with self.assertRaises(runtime.PraiseError):
            runtime.add_reproduction(eng, candidate_id, "third", "clean-C", "copied.json", DS_PRO)
        self.assertEqual(len(runtime.get_candidate(eng, candidate_id)["reproductions"]), 1)


class TransitionRaceTests(RuntimeTestBase):
    def _gated(self):
        _, eng = self._init_source()
        candidate = self._new_source_candidate(eng)
        runtime.gate_candidate(eng, candidate["id"], "pass", "trace", MIMO)
        return eng, candidate["id"]

    def _interleave(self, late, early):
        ready = threading.Event()
        release = threading.Event()
        original = runtime._tx
        errors = []

        @contextlib.contextmanager
        def delayed(conn):
            if threading.current_thread().name == "late-transition":
                ready.set()
                if not release.wait(5):
                    raise AssertionError("transaction was not released")
            with original(conn):
                yield

        def worker():
            try:
                late()
            except runtime.PraiseError as error:
                errors.append(error)

        with patch.object(runtime, "_tx", delayed):
            thread = threading.Thread(target=worker, name="late-transition")
            thread.start()
            try:
                self.assertTrue(ready.wait(5), "transition did not reach its write transaction")
                early()
            finally:
                release.set()
                thread.join(5)
            self.assertFalse(thread.is_alive())
        return errors

    def test_late_proof_cannot_resurrect_a_rejected_case(self):
        eng, candidate_id = self._gated()
        self._write_evidence(eng, "late.json", b"late-proof")
        errors = self._interleave(
            lambda: runtime.add_reproduction(eng, candidate_id, "late", "clean-A", "late.json", DS_PRO),
            lambda: runtime.record_verdict(eng, candidate_id, "rejected", "independent rejection", GLM),
        )
        case = runtime.get_candidate(eng, candidate_id)
        self.assertEqual(case["status"], "rejected")
        self.assertEqual(case["reproductions"], [])
        self.assertEqual(len(errors), 1)

    def test_verdict_uses_producers_present_at_commit(self):
        eng, candidate_id = self._gated()
        for index in range(3):
            self._write_evidence(eng, f"proof-{index}.json", f"proof-{index}".encode())
        for index in range(2):
            runtime.add_reproduction(eng, candidate_id, f"r{index}", f"clean-{index}", f"proof-{index}.json", DS_PRO)
        errors = self._interleave(
            lambda: runtime.record_verdict(eng, candidate_id, "confirmed", "review", GLM),
            lambda: runtime.add_reproduction(eng, candidate_id, "r2", "clean-2", "proof-2.json", GLM),
        )
        self.assertEqual(runtime.get_candidate(eng, candidate_id)["status"], "reproduced")
        self.assertEqual(len(errors), 1)


class DispatchTests(RuntimeTestBase):
    def _packet(self, eng, candidate=None, ref="packet.json", **extra):
        data = {"hypothesis": "input reaches sink", "question": "resolve the missing boundary",
                "relevant_sources": ["src/a.py:10", "src/b.py:20"], "observations": ["branch not resolved"],
                "evidence": ["e1.json"], "proof_status": "unresolved", "finding_id": candidate}
        data.update(extra)
        self._write_evidence(eng, ref, json.dumps(data).encode())
        return ref

    def _attempt(self, eng, candidate, tier="normal", packet="packet.json", **extra):
        roles = runtime.load_roles()
        worker = roles["stages" if tier == "normal" else "escalations" if tier == "deep" else "experts"]["discover"]
        model = roles["roles"][worker]["models"][0]
        sender = runtime.register_agent(eng, "session-" + tier, worker, "discover", model, candidate)["agent"]
        data = {"status": "unresolved", "finding_id": candidate, "worker": worker, "tier": tier,
                "hypothesis": "input reaches sink", "unresolved_questions": ["missing branch"],
                "evidence": ["e1.json"], "packet": packet}
        data.update(extra)
        return runtime.send_message(eng, sender, model, "@lead", "close", data, candidate,
                                    evidence=["e1.json", packet])["seq"]

    def test_proof_dispatch_requires_gated(self):
        _, eng = self._init_source()
        cand = self._new_source_candidate(eng)
        with self.assertRaises(runtime.PraiseError):
            runtime.dispatch(eng, "proof", candidate_id=cand["id"])
        runtime.gate_candidate(eng, cand["id"], "pass", "ok", MIMO)
        self.assertEqual(runtime.dispatch(eng, "proof", cand["id"])["stage"], "proof")

    def test_verdict_no_fallback_on_family_conflict(self):
        _, eng = self._init_source()
        roles = runtime.load_roles()
        checker_model = roles["roles"][roles["stages"]["verdict"]]["models"][0]
        cand = self._new_source_candidate(eng, producer=checker_model)
        with self.assertRaises(runtime.PraiseError):
            runtime.dispatch(eng, "verdict", cand["id"])

    def test_verdict_dispatch_selects_independent_configured_model(self):
        _, eng = self._init_source()
        cand = self._new_source_candidate(eng, producer=DS_FLASH)
        result = runtime.dispatch(eng, "verdict", cand["id"])
        self.assertNotEqual(result["family"], runtime.model_family(DS_FLASH))

    def test_dispatch_requires_candidate_and_attested_engagement(self):
        _, eng = self._init_source()
        with self.assertRaises(runtime.PraiseError):
            runtime.dispatch(eng, "verdict")
        with self.assertRaises(runtime.PraiseError):
            runtime.dispatch(self.root, "plan")

    def test_escalation_cannot_skip_predecessor_or_use_confidence(self):
        _, eng = self._init_source()
        candidate = self._new_source_candidate(eng)["id"]
        packet = self._packet(eng, candidate)
        with self.assertRaises(runtime.PraiseError):
            runtime.dispatch(eng, "discover", candidate, tier="deep", reason="important", packet=packet)
        attempt = self._attempt(eng, candidate, confidence=0.99)
        with self.assertRaises(runtime.PraiseError):
            runtime.dispatch(eng, "discover", candidate, tier="expert", reason="complex", packet=packet, attempt=attempt)
        with self.assertRaises(runtime.PraiseError):
            runtime.dispatch(eng, "discover", candidate, False, "gap", tier="deep", packet=packet, attempt=attempt)
        result = runtime.dispatch(eng, "discover", candidate, True, "missing branch", packet=packet, attempt=attempt)
        self.assertEqual(result["agent"], runtime.load_roles()["escalations"]["discover"])
        self.assertEqual(result["packet"]["data"]["finding_id"], candidate)

    def test_each_expert_tier_requires_current_predecessor(self):
        _, eng = self._init_source()
        candidate = self._new_source_candidate(eng)["id"]
        roles = runtime.load_roles()
        for previous, target in (("normal", "deep"), ("deep", "expert"), ("expert", "expert-max")):
            packet = self._packet(eng, candidate, ref=previous + ".json")
            attempt = self._attempt(eng, candidate, previous, packet)
            result = runtime.dispatch(eng, "discover", candidate, tier=target, reason="missing branch",
                                      packet=packet, attempt=attempt)
            agent = roles["escalations" if target == "deep" else "experts"]["discover"]
            expected = roles["roles"][agent]["max_model"] if target == "expert-max" else roles["roles"][agent]["models"][0]
            self.assertEqual(result["model"], expected)
            self.assertEqual(result["tier"], target)

    def test_explicit_max_identity_cannot_claim_a_high_predecessor(self):
        _, eng = self._init_source()
        candidate = self._new_source_candidate(eng)["id"]
        packet = self._packet(eng, candidate)
        roles = runtime.load_roles()
        worker = roles["experts"]["discover"]
        model = roles["roles"][worker]["max_model"]
        actor = runtime.register_agent(eng, "wrong-effort", worker, "discover", model, candidate)["agent"]
        data = {"status": "unresolved", "finding_id": candidate, "worker": worker, "tier": "expert",
                "unresolved_questions": ["unresolved branch"]}
        attempt = runtime.send_message(eng, actor, model, "@lead", "close", data, candidate,
                                       evidence=["e1.json", packet])["seq"]
        with self.assertRaises(runtime.PraiseError):
            runtime.dispatch(eng, "discover", candidate, tier="expert-max", reason="gap",
                             packet=packet, attempt=attempt)

    def test_stale_packet_and_superseded_attempt_fail_closed(self):
        _, eng = self._init_source()
        candidate = self._new_source_candidate(eng)["id"]
        packet = self._packet(eng, candidate)
        attempt = self._attempt(eng, candidate)
        self._packet(eng, candidate, question="a different question")
        with self.assertRaises(runtime.PraiseError):
            runtime.dispatch(eng, "discover", candidate, tier="deep", reason="gap", packet=packet, attempt=attempt)
        self._attempt(eng, candidate)
        with self.assertRaises(runtime.PraiseError):
            runtime.dispatch(eng, "discover", candidate, tier="deep", reason="gap", packet=packet, attempt=attempt)

    def test_packet_rejects_transcripts_unknown_fields_and_escape(self):
        _, eng = self._init_source()
        candidate = self._new_source_candidate(eng)["id"]
        for extra in ({"history": ["entire conversation"]}, {"hypothesis": "x" * 1025},
                      {"evidence": ["../outside.json"]}, {"finding_id": "different"}):
            packet = self._packet(eng, candidate, **extra)
            with self.assertRaises((runtime.PraiseError, ValueError)):
                runtime.dispatch(eng, "discover", candidate, tier="deep", reason="gap", packet=packet, attempt=1)

    def test_refusal_cannot_be_rejection_or_max_substantive_gap(self):
        _, eng = self._init_source()
        candidate = self._new_source_candidate(eng)["id"]
        packet = self._packet(eng, candidate)
        with self.assertRaises(runtime.PraiseError):
            self._attempt(eng, candidate, status="rejected", execution_failure="refusal")
        attempt = self._attempt(eng, candidate, "expert", packet, execution_failure="refusal", unresolved_questions=[])
        with self.assertRaises(runtime.PraiseError):
            runtime.dispatch(eng, "discover", candidate, tier="expert-max", reason="retry", packet=packet, attempt=attempt)

    def test_predecessor_observed_model_and_substantive_gap_are_required(self):
        _, eng = self._init_source()
        candidate = self._new_source_candidate(eng)["id"]
        packet = self._packet(eng, candidate)
        attempt = self._attempt(eng, candidate, unresolved_questions=[], confidence=1.0, complexity="high")
        with self.assertRaises(runtime.PraiseError):
            runtime.dispatch(eng, "discover", candidate, tier="deep", reason="important", packet=packet, attempt=attempt)
        worker = runtime.load_roles()["stages"]["discover"]
        wrong = runtime.register_agent(eng, "wrong-model", worker, "discover", GLM, candidate)["agent"]
        data = {"worker": worker, "tier": "normal", "finding_id": candidate, "status": "unresolved",
                "packet": packet, "unresolved_questions": ["missing branch"]}
        attempt = runtime.send_message(eng, wrong, GLM, "@lead", "close", data, candidate,
                                       evidence=["e1.json", packet])["seq"]
        with self.assertRaises(runtime.PraiseError):
            runtime.dispatch(eng, "discover", candidate, tier="deep", reason="gap", packet=packet, attempt=attempt)

    def test_lead_can_create_narrower_packet_after_worker_report(self):
        _, eng = self._init_source()
        candidate = self._new_source_candidate(eng)["id"]
        original = self._packet(eng, candidate)
        attempt = self._attempt(eng, candidate)
        model = runtime.load_roles()["lead_model"]
        lead = runtime.register_agent(eng, "lead", "Lead", "lead", model)["agent"]
        with open(os.path.join(eng, "evidence", original), encoding="utf-8") as fh:
            data = json.load(fh)
        data["question"] = "only inspect the missing authorization branch"
        created = runtime.create_packet(eng, data, model, lead)
        self.assertEqual(created, runtime.create_packet(eng, data, model, lead))
        result = runtime.dispatch(eng, "discover", candidate, tier="deep", reason="missing branch",
                                  packet=created["ref"], attempt=attempt)
        self.assertEqual(result["packet"]["sha256"], created["sha256"])
        self._write_evidence(eng, "unanchored.json", b"new unreviewed observation")
        data["evidence"] = ["unanchored.json"]
        unrelated = runtime.create_packet(eng, data, model, lead)
        with self.assertRaises(runtime.PraiseError):
            runtime.dispatch(eng, "discover", candidate, tier="deep", reason="gap",
                             packet=unrelated["ref"], attempt=attempt)

    def test_packet_creator_is_bounded_confined_and_never_clobbers(self):
        _, eng = self._init_source()
        candidate = self._new_source_candidate(eng)["id"]
        original = self._packet(eng, candidate)
        with open(os.path.join(eng, "evidence", original), encoding="utf-8") as fh:
            data = json.load(fh)
        created = runtime.create_packet(eng, data, DS_FLASH)
        self.assertEqual(created["ref"], "packet-" + created["sha256"] + ".json")
        self._write_evidence(eng, created["ref"], b"tampered")
        with self.assertRaises(runtime.PraiseError):
            runtime.create_packet(eng, data, DS_FLASH)
        for bad in ({**data, "history": ["chat"]}, {**data, "evidence": ["../outside"]},
                    {**data, "source_excerpts": ["界" * 1000]}):
            with self.assertRaises((runtime.PraiseError, ValueError)):
                runtime.create_packet(eng, bad, DS_FLASH)

    def test_deep_independence_exception_requires_current_two_proofs(self):
        _, eng = self._init_source()
        roles = runtime.load_roles()
        checker_model = roles["roles"][roles["stages"]["verdict"]]["models"][0]
        candidate = self._new_source_candidate(eng, producer=checker_model)["id"]
        packet = self._packet(eng, candidate)
        runtime.gate_candidate(eng, candidate, "pass", "source path", DS_FLASH)
        with self.assertRaises(runtime.PraiseError):
            runtime.dispatch(eng, "verdict", candidate, tier="deep", reason="family conflict", packet=packet)
        for index in range(2):
            ref = f"proof-{index}.json"
            self._write_evidence(eng, ref, f"clean-state evidence {index}".encode())
            runtime.add_reproduction(eng, candidate, f"run-{index}", f"clean-{index}", ref, DS_FLASH)
        result = runtime.dispatch(eng, "verdict", candidate, tier="deep", reason="family conflict", packet=packet)
        self.assertNotIn(result["family"], {runtime.model_family(checker_model), runtime.model_family(DS_FLASH)})
        self._write_evidence(eng, "proof-0.json", b"changed")
        with self.assertRaises(runtime.PraiseError):
            runtime.dispatch(eng, "verdict", candidate, tier="deep", reason="family conflict", packet=packet)


class FinalReviewTests(RuntimeTestBase):
    _packet = DispatchTests._packet

    def _confirmed(self, name="eng"):
        _, eng = self._init_source(name)
        candidate = self._new_source_candidate(eng)["id"]
        runtime.gate_candidate(eng, candidate, "pass", "reachable", DS_FLASH)
        for index in range(2):
            ref = f"proof-{index}.json"
            self._write_evidence(eng, ref, f"clean proof {index}".encode())
            runtime.add_reproduction(eng, candidate, f"run-{index}", f"clean-{index}", ref, DS_FLASH)
        self._write_evidence(eng, "verdict.json", b"independent evidence analysis")
        runtime.record_verdict(eng, candidate, "confirmed", "two clean proofs", GLM, ["verdict.json"])
        return eng, candidate

    def test_current_proof_change_invalidates_final_review_readiness(self):
        eng, candidate = self._confirmed()
        model = runtime.load_roles()["roles"][runtime.load_roles()["stages"]["review"]]["models"][0]
        self._write_evidence(eng, "review.json", b"independent current review")
        runtime.record_review(eng, candidate, "approved", "current evidence", model, ["review.json"])
        self._write_evidence(eng, "proof-0.json", b"changed proof")
        state = runtime.show(eng, candidate)["candidate"]
        self.assertEqual(state["review_status"], "stale")
        self.assertFalse(state["report_ready"])
        with self.assertRaises(runtime.PraiseError):
            runtime.record_review(eng, candidate, "approved", "cannot refresh stale proof", model, ["review.json"])

    def test_review_packet_requires_current_representative_proof_pair_only(self):
        eng, candidate = self._confirmed()
        packet = self._packet(eng, candidate, proof_status="confirmed")
        with self.assertRaises(runtime.PraiseError):
            runtime.dispatch(eng, "review", candidate, packet=packet)
        self._write_evidence(eng, "unrelated.json", b"unrelated engagement artifact")
        packet = self._packet(eng, candidate, proof_status="confirmed",
                              evidence=["proof-0.json", "proof-1.json", "unrelated.json"])
        with self.assertRaises(runtime.PraiseError):
            runtime.dispatch(eng, "review", candidate, packet=packet)
        packet = self._packet(eng, candidate, proof_status="confirmed", evidence=["proof-0.json", "proof-1.json"])
        selected = runtime.dispatch(eng, "review", candidate, packet=packet)
        self.assertEqual(set(selected["case"]), {"id", "status", "producer_models", "review_status", "report_ready"})

    def test_confirmed_case_requires_current_approved_review_for_report_and_patch(self):
        eng, candidate = self._confirmed()
        packet = self._packet(eng, candidate, proof_status="confirmed",
                              evidence=["e1.json", "proof-0.json", "proof-1.json"])
        self.assertFalse(runtime.show(eng, candidate)["candidate"]["report_ready"])
        with self.assertRaises(runtime.PraiseError):
            runtime.dispatch(eng, "patch", candidate)
        selected = runtime.dispatch(eng, "review", candidate, packet=packet)
        reviewer = runtime.register_agent(eng, "reviewer", selected["agent"], "review", selected["model"], candidate)["agent"]
        self._write_evidence(eng, "review.json", b"review: current proofs independently assessed")
        result = runtime.record_review(eng, candidate, "approved", "current evidence reviewed", selected["model"],
                                       ["review.json"], reviewer)
        self.assertTrue(result["report_ready"])
        self.assertEqual(result["_messages"][0]["to"], "@patch")
        self.assertEqual(runtime.show(eng, candidate, compact=True)["candidate"]["review_status"], "approved")
        self.assertEqual(runtime.dispatch(eng, "patch", candidate)["stage"], "patch")
        self._write_evidence(eng, "review.json", b"changed")
        self.assertFalse(runtime.get_candidate(eng, candidate)["report_ready"])
        with self.assertRaises(runtime.PraiseError):
            runtime.dispatch(eng, "patch", candidate)

    def test_review_cannot_run_on_source_only_or_reuse_case_evidence(self):
        _, eng = self._init_source()
        candidate = self._new_source_candidate(eng)["id"]
        packet = self._packet(eng, candidate)
        with self.assertRaises(runtime.PraiseError):
            runtime.dispatch(eng, "review", candidate, packet=packet)
        eng, candidate = self._confirmed("confirmed")
        model = runtime.load_roles()["roles"][runtime.load_roles()["stages"]["review"]]["models"][0]
        with self.assertRaises(runtime.PraiseError):
            runtime.record_review(eng, candidate, "approved", "reuse", model, ["proof-0.json"])
        with self.assertRaises(runtime.PraiseError):
            runtime.record_review(eng, candidate, "approved", "no own evidence", model, [])

    def test_new_review_decision_supersedes_readiness_without_reopening_verdict(self):
        eng, candidate = self._confirmed()
        model = runtime.load_roles()["roles"][runtime.load_roles()["stages"]["review"]]["models"][0]
        self._write_evidence(eng, "review.json", b"independent review")
        runtime.record_review(eng, candidate, "approved", "approved", model, ["review.json"])
        self._write_evidence(eng, "challenge.json", b"review identifies unanswered boundary")
        result = runtime.record_review(eng, candidate, "needs-more-proof", "boundary unresolved", model, ["challenge.json"])
        self.assertFalse(result["report_ready"])
        self.assertEqual(runtime.get_candidate(eng, candidate)["status"], "confirmed")
        self.assertEqual(result["_messages"][0]["to"], "@lead")

    def test_explicit_max_cannot_approve_the_high_review_lane(self):
        eng, candidate = self._confirmed()
        roles = runtime.load_roles()
        model = roles["roles"][roles["escalations"]["verdict"]]["models"][0]
        self._write_evidence(eng, "review.json", b"independent synthetic review")
        with self.assertRaises(runtime.PraiseError):
            runtime.record_review(eng, candidate, "approved", "wrong effort", model, ["review.json"])


class MessageTests(RuntimeTestBase):
    def _agent(self, eng, session, role="discover", model=DS_FLASH, candidate=None):
        return runtime.register_agent(eng, session, session, role, model, candidate)["agent"]

    def test_addressed_messages_and_replies_do_not_advance_candidates(self):
        _, eng = self._init_source()
        finder = self._agent(eng, "finder")
        candidate = self._new_source_candidate(eng, producer=DS_FLASH, producer_agent=finder)["id"]
        gate = self._agent(eng, "gate", "gate", MIMO, candidate)
        outsider = self._agent(eng, "outsider", "proof", DS_PRO, candidate)
        sent = runtime.send_message(eng, finder, DS_FLASH, gate, "ask", {"need": "reachability"}, candidate)
        received = runtime.inbox(eng, gate)
        question = next(m for m in received["messages"] if m["seq"] == sent["seq"])
        self.assertEqual(question["data"], {"need": "reachability"})
        self.assertEqual(runtime.get_candidate(eng, candidate)["status"], "candidate")
        self.assertEqual(runtime.inbox(eng, outsider)["messages"], [])
        with self.assertRaises(runtime.PraiseError):
            runtime.send_message(eng, outsider, DS_PRO, finder, "reply", {"answer": "spoof"}, candidate, sent["seq"])
        reply = runtime.send_message(eng, gate, MIMO, finder, "reply", {"reachable": True}, candidate, sent["seq"])
        self.assertEqual(runtime.inbox(eng, finder)["messages"][-1]["reply"], sent["seq"])
        self.assertGreater(reply["seq"], sent["seq"])

    def test_retries_are_idempotent_but_changed_content_is_rejected(self):
        _, eng = self._init_source()
        sender = self._agent(eng, "sender")
        recipient = self._agent(eng, "recipient", "gate", MIMO)
        first = runtime.send_message(eng, sender, DS_FLASH, recipient, "ask", {"need": "trace"}, key="call-1")
        repeated = runtime.send_message(eng, sender, DS_FLASH, recipient, "ask", {"need": "trace"}, key="call-1")
        self.assertEqual(repeated["seq"], first["seq"])
        self.assertTrue(repeated["duplicate"])
        self.assertEqual(repeated["_messages"], [])
        with self.assertRaises(runtime.PraiseError):
            runtime.send_message(eng, sender, DS_FLASH, recipient, "ask", {"need": "different"}, key="call-1")
        self.assertEqual([m["seq"] for m in runtime.inbox(eng, recipient)["messages"]], [first["seq"]])

    def test_inbox_pagination_preserves_old_handoffs_and_skips_unrelated_tasks(self):
        _, eng = self._init_source()
        sender = self._agent(eng, "sender")
        recipient = self._agent(eng, "recipient", "gate", MIMO)
        other = self._agent(eng, "other", "proof", DS_PRO)
        expected = []
        for index in range(40):
            expected.append(runtime.send_message(eng, sender, DS_FLASH, recipient, "ask", {"index": index})["seq"])
            runtime.send_message(eng, sender, DS_FLASH, other, "close", {"unrelated": index})
        cursor, received = 0, []
        while True:
            page = runtime.inbox(eng, recipient, cursor, 7)
            received.extend(m["seq"] for m in page["messages"])
            self.assertLessEqual(len(json.dumps(page, ensure_ascii=False, separators=(",", ":")).encode()), runtime.MAX_INBOX_BYTES)
            cursor = page["cursor"]
            if not page["more"]:
                break
        self.assertEqual(received, expected)
        self.assertEqual(runtime.inbox(eng, recipient, cursor)["messages"], [])

    def test_new_commit_cannot_be_skipped_by_an_empty_page_high_water_mark(self):
        _, eng = self._init_source()
        sender = self._agent(eng, "sender")
        recipient = self._agent(eng, "recipient", "gate", MIMO)
        reader = runtime.connect(eng)
        inserted = []
        def commit_between_page_and_cursor(sql):
            if "MAX(seq)" not in sql or inserted:
                return
            writer = sqlite3.connect(os.path.join(eng, "state.sqlite3"), isolation_level=None)
            writer.row_factory = sqlite3.Row
            try:
                with runtime._tx(writer):
                    inserted.append(runtime.emit_message(
                        writer, role="discover", model=DS_FLASH, sender=sender, to=recipient,
                        kind="ask", data={"need": "late trace"},
                    )["seq"])
            finally:
                writer.close()
        reader.set_trace_callback(commit_between_page_and_cursor)
        with patch.object(runtime, "connect", return_value=reader):
            empty = runtime.inbox(eng, recipient)
        self.assertEqual(empty["messages"], [])
        recovered = runtime.inbox(eng, recipient, empty["cursor"])
        self.assertEqual([m["seq"] for m in recovered["messages"]], inserted)

    def test_message_bounds_identity_and_reserved_event_kind(self):
        _, eng = self._init_source()
        sender = self._agent(eng, "sender")
        for kind, data, model, target in (
            ("event", {"event": "gate.passed"}, DS_FLASH, "@proof"),
            ("ask", {"text": "界" * 700}, DS_FLASH, "@lead"),
            ("ask", {"number": float("nan")}, DS_FLASH, "@lead"),
            ("ask", {}, GPT, "@lead"),
            ("ask", {}, DS_FLASH, "a9999"),
        ):
            with self.assertRaises(runtime.PraiseError):
                runtime.send_message(eng, sender, model, target, kind, data)
        with self.assertRaises(runtime.PraiseError):
            runtime.register_agent(eng, "sender", "sender", "proof", DS_FLASH)
        with self.assertRaises(runtime.PraiseError):
            runtime.register_agent(eng, "bad", "forged\n### entry", "discover", DS_FLASH)
        lead = self._agent(eng, "lead", "lead", GPT)
        self.assertEqual(runtime.inbox(eng, lead)["messages"], [])

    def test_concurrent_messages_project_once_in_commit_order(self):
        _, eng = self._init_source()
        sender = self._agent(eng, "sender")
        lead = self._agent(eng, "lead", "lead", GPT)
        with ThreadPoolExecutor(max_workers=8) as workers:
            messages = list(workers.map(
                lambda index: runtime.send_message(
                    eng, sender, DS_FLASH, lead, "close", {"index": index, "text": "\n### forged-entry"},
                ),
                range(16),
            ))
        runtime.project_messages(eng)
        self.assertEqual(runtime.project_messages(eng)["projected"], 0)
        with open(os.path.join(eng, "agentschat.md"), encoding="utf-8") as fh:
            headers = [line for line in fh if line.startswith("### ")]
        self.assertEqual(
            [int(line.rsplit("seq=", 1)[1]) for line in headers],
            sorted(m["seq"] for m in messages),
        )
        self.assertEqual([m["data"]["index"] for m in runtime.inbox(eng, lead)["messages"]],
                         [m["data"]["index"] for m in sorted((m["_messages"][0] for m in messages), key=lambda m: m["seq"])])

    def test_workflow_topics_case_filter_and_transactional_handoff(self):
        _, eng = self._init_source()
        finder = self._agent(eng, "finder")
        first = self._new_source_candidate(eng, producer=DS_FLASH, producer_agent=finder)["id"]
        second = self._new_source_candidate(eng, producer=DS_FLASH, producer_agent=finder)["id"]
        gate = self._agent(eng, "gate", "gate", MIMO, first)
        self.assertEqual([m["case"] for m in runtime.inbox(eng, gate)["messages"]], [first])
        with patch.object(runtime, "emit_message", side_effect=RuntimeError("disk fixture failure")):
            with self.assertRaises(RuntimeError):
                runtime.gate_candidate(eng, first, "pass", "reachable", MIMO, gate)
        self.assertEqual(runtime.get_candidate(eng, first)["status"], "candidate")
        held = runtime.gate_candidate(eng, first, "hold", "missing ownership proof", MIMO, gate)
        self.assertEqual(runtime.inbox(eng, finder)["messages"][-1]["data"]["event"], "gate.held")
        self.assertEqual(held["_messages"][0]["to"], finder)
        runtime.gate_candidate(eng, first, "pass", "trace complete", MIMO, gate)
        proof = self._agent(eng, "proof", "proof", DS_PRO, first)
        self.assertEqual(runtime.inbox(eng, proof)["messages"][-1]["data"]["event"], "gate.passed")
        self.assertEqual(runtime.get_candidate(eng, second)["status"], "candidate")
        lead = self._agent(eng, "lead", "lead", GPT)
        runtime.gate_candidate(eng, second, "drop", "fixture false positive", MIMO)
        closed = [m for m in runtime.inbox(eng, lead)["messages"] if m["to"] == "@learning"]
        self.assertEqual([(m["case"], m["data"]["next"]) for m in closed], [(second, "learn.observe")])

    def test_v1_migration_preserves_events_history_and_audit(self):
        _, eng = self._init_source()
        conn = sqlite3.connect(os.path.join(eng, "state.sqlite3"))
        try:
            conn.executescript("""
                DROP TABLE messages;
                DROP TABLE participants;
                ALTER TABLE candidates DROP COLUMN producer_agent;
                ALTER TABLE reproductions DROP COLUMN producer_agent;
                CREATE TABLE events (seq INTEGER PRIMARY KEY AUTOINCREMENT, role TEXT, model TEXT,
                    summary TEXT, ask TEXT, close TEXT, evidence_json TEXT, created_at TEXT);
                UPDATE meta SET value='1' WHERE key='schema_version';
            """)
            conn.execute("INSERT INTO events VALUES (7,?,?,?,?,?,?,?)",
                         ("finder", DS_FLASH, "preserved", "gate candidate", None, "[]", "2026-10-01T00:00:00+00:00"))
            conn.commit()
        finally:
            conn.close()
        log = os.path.join(eng, "agentschat.md")
        with open(log, "w", encoding="utf-8") as fh:
            fh.write("original audit\n### 2026-10-01T00:00:00Z | finder | fixture | eng | seq=7\nASK: gate candidate\n\n")
        lead = self._agent(eng, "lead", "lead", GPT)
        self.assertEqual(runtime.inbox(eng, lead)["messages"], [])
        conn = runtime.connect(eng)
        try:
            migrated = conn.execute("SELECT * FROM messages WHERE seq=7").fetchone()
            self.assertEqual(json.loads(migrated["data_json"]), {"summary": "preserved", "ask": "gate candidate"})
            self.assertEqual((migrated["model"], migrated["created_at"]), (DS_FLASH, "2026-10-01T00:00:00+00:00"))
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0], 1)
        finally:
            conn.close()
        runtime.register_agent(eng, "lead", "lead", "lead", GPT)
        sent = runtime.send_message(eng, lead, GPT, lead, "ask", {"need": "new work"})
        self.assertEqual([m["seq"] for m in runtime.inbox(eng, lead)["messages"]], [sent["seq"]])
        runtime.project_messages(eng)
        with open(log, encoding="utf-8") as fh:
            audit = fh.read()
        self.assertTrue(audit.startswith("original audit\n"))
        self.assertEqual(audit.count("seq=7"), 1)

    def test_compact_state_is_whole_bounded_data_not_shared_chat(self):
        _, eng = self._init_source()
        for index in range(18):
            self._new_source_candidate(eng, id=f"C-{index}")
        state = runtime.show(eng, compact=True)
        self.assertEqual(state["counts"], {"candidate": 18})
        self.assertTrue(state["more"])
        self.assertEqual(len(state["candidates"]), 16)
        self.assertLessEqual(len(json.dumps(state, separators=(",", ":")).encode()), 4096)
        candidate = runtime.show(eng, "C-0", compact=True)["candidate"]
        self.assertEqual(candidate["source_ref"], "src/a.py:10")
        self.assertEqual(candidate["refs"], ["e1.json"])


class ResidentTransportTests(RuntimeTestBase):
    def test_bound_process_handles_multiple_commands_and_survives_a_refusal(self):
        _, eng = self._init_source()
        _, sibling = self._init_source("sibling")
        packets = [
            {"id": 1, "args": ["register", "--session", "finder", "--name", "finder", "--role", "discover", "--model", DS_FLASH]},
            {"id": 2, "args": ["register", "--session", "gate", "--name", "gate", "--role", "gate", "--model", MIMO]},
            {"id": 3, "args": ["message", "--from", "a1", "--model", DS_FLASH, "--to", "a2", "--kind", "ask", "--data", '{"need":"trace"}']},
            {"id": 4, "args": ["show", "--engagement", sibling]},
            {"id": 5, "args": ["inbox", "--agent", "a2"]},
            {"id": 6, "args": ["lead", "--", "--mode", "rpc", "--no-session", "--no-ui"]},
        ]
        result = subprocess.run(
            [sys.executable, "-m", "praise", "--engagement", eng, "serve"],
            input="".join(json.dumps(p) + "\n" for p in packets), text=True, capture_output=True,
            cwd=os.path.dirname(os.path.dirname(__file__)), timeout=15, check=True,
        )
        replies = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual([r["id"] for r in replies], [1, 2, 3, 4, 5, 6])
        self.assertFalse(replies[3]["ok"])
        self.assertEqual(replies[4]["data"]["messages"][0]["data"], {"need": "trace"})
        self.assertFalse(replies[5]["ok"])
        self.assertEqual(runtime.peers(sibling)["agents"], [])


class FixValidationTests(RuntimeTestBase):
    def _gates(self, overrides=None):
        gates = {
            "root_cause": {"status": "pass", "evidence": ["e1.json"]},
            "instance_coverage": {"status": "pass", "evidence": ["e1.json"]},
            "no_new_vulnerabilities": {"status": "pass", "evidence": ["e1.json"]},
            "security_best_practices": {"status": "pass", "evidence": ["e1.json"]},
        }
        if overrides:
            gates.update(overrides)
        return gates

    def test_all_pass_is_fixed(self):
        _, eng = self._init_source()
        cand = self._new_source_candidate(eng)
        result = runtime.validate_fix(eng, cand["id"], GLM, self._gates())
        self.assertEqual(result["result"], "fixed")

    def test_failed_gate_never_fixed(self):
        _, eng = self._init_source()
        cand = self._new_source_candidate(eng)
        gates = self._gates({"no_new_vulnerabilities": {"status": "fail", "evidence": []}})
        gates["score"] = 0.99  # score must never override a failed gate
        result = runtime.validate_fix(eng, cand["id"], GLM, gates)
        self.assertEqual(result["result"], "not-fixed")

    def test_partial_gate_is_not_fixed(self):
        _, eng = self._init_source()
        cand = self._new_source_candidate(eng)
        result = runtime.validate_fix(
            eng, cand["id"], GLM, self._gates({"root_cause": {"status": "partial", "evidence": []}})
        )
        self.assertEqual(result["result"], "not-fixed")

    def test_missing_gate_unverifiable(self):
        _, eng = self._init_source()
        cand = self._new_source_candidate(eng)
        gates = self._gates()
        del gates["security_best_practices"]
        result = runtime.validate_fix(eng, cand["id"], GLM, gates)
        self.assertEqual(result["result"], "unverifiable")

    def test_skip_gate_unverifiable(self):
        _, eng = self._init_source()
        cand = self._new_source_candidate(eng)
        result = runtime.validate_fix(
            eng, cand["id"], GLM, self._gates({"instance_coverage": {"status": "skip", "evidence": []}})
        )
        self.assertEqual(result["result"], "unverifiable")

    def test_pass_without_evidence_is_unverifiable(self):
        _, eng = self._init_source()
        candidate = self._new_source_candidate(eng)
        result = runtime.validate_fix(
            eng, candidate["id"], GLM, self._gates({"root_cause": {"status": "pass", "evidence": []}})
        )
        self.assertEqual(result["result"], "unverifiable")
        self.assertEqual(result["gates"]["root_cause"], "missing-evidence")


class URLBoundaryTests(RuntimeTestBase):
    ASSET = "http://127.0.0.1:8000/api/v1"

    def test_exact_origin_and_prefix(self):
        self.assertTrue(policy.url_allowed(self.ASSET, "http://127.0.0.1:8000/api/v1/users"))
        self.assertTrue(policy.url_allowed(self.ASSET, "http://127.0.0.1:8000/api/v1"))
        self.assertFalse(policy.url_allowed(self.ASSET, "http://127.0.0.1:8000/api/v1evil"))
        self.assertFalse(policy.url_allowed(self.ASSET, "http://127.0.0.1:8000/api/v2"))
        self.assertFalse(policy.url_allowed(self.ASSET, "http://127.0.0.1:8000/api"))
        self.assertFalse(policy.url_allowed(self.ASSET, "http://127.0.0.1:8001/api/v1"))
        self.assertFalse(policy.url_allowed(self.ASSET, "https://127.0.0.1:8000/api/v1"))
        self.assertFalse(policy.url_allowed(self.ASSET, "http://localhost:8000/api/v1"))

    def test_origin_root_covers_descendants_but_not_other_origins(self):
        self.assertTrue(policy.url_allowed("http://127.0.0.1:8000/", "http://127.0.0.1:8000/records/one"))
        self.assertFalse(policy.url_allowed("http://127.0.0.1:8000/", "http://127.0.0.1:8001/records/one"))

    def test_reject_credentials_and_traversal(self):
        with self.assertRaises(ValueError):
            policy.split_url("http://user:pass@127.0.0.1:8000/api/v1")
        with self.assertRaises(ValueError):
            policy.split_url("http://127.0.0.1:8000/api/../secret")
        with self.assertRaises(ValueError):
            policy.split_url("http://127.0.0.1:8000/api/%2e%2e/secret")


class HTTPRequestTests(RuntimeTestBase):
    def setUp(self):
        super().setUp()
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self.httpd.server_address[1]
        self.httpd.hits = []
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        super().tearDown()

    def _blackbox(self, max_requests=10, interval=0.0):
        eng = os.path.join(self.root, "eng")
        return runtime.init_engagement(
            eng,
            program="p",
            basis="b",
            assets=[f"http://127.0.0.1:{self.port}/api/v1"],
            mode="blackbox",
            max_requests=max_requests,
            interval_seconds=interval,
        ), eng

    def test_in_scope_request_records_minimal_artifact(self):
        scope, eng = self._blackbox()
        result = runtime.perform_request(
            eng, f"http://127.0.0.1:{self.port}/api/v1/ok", role="scout", model=DS_FLASH
        )
        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["content_length"], 2)
        art = runtime.artifact(eng, result["artifact_ref"])
        with open(art["path"], encoding="utf-8") as fh:
            persisted = json.load(fh)
        self.assertEqual(result["response_body"], "ok")
        self.assertEqual(persisted["response_body"], "ok")

    def test_credentials_are_redacted_without_losing_the_witness(self):
        _, eng = self._blackbox()
        result = runtime.perform_request(
            eng, f"http://127.0.0.1:{self.port}/api/v1/secrets?token=query-control",
            headers={"Authorization": "Bearer supplied-control"}, role="scout", model=DS_FLASH,
        )
        art = runtime.artifact(eng, result["artifact_ref"])
        with open(art["path"], encoding="utf-8") as fh:
            persisted = json.load(fh)
        self.assertEqual(persisted["response_body"]["witness"], "synthetic record")
        self.assertEqual(persisted["response_body"]["nested"]["password"], "<redacted>")
        for secret in ("response-only-control", "nested-control", "supplied-control", "query-control"):
            self.assertNotIn(secret, json.dumps(persisted))
            self.assertNotIn(secret, json.dumps(result))
        conn = runtime.connect(eng)
        try:
            self.assertNotIn("query-control", conn.execute("SELECT url FROM request_log").fetchone()[0])
        finally:
            conn.close()

    def test_host_override_and_framing_headers_never_reach_the_server(self):
        _, eng = self._blackbox()
        for name in ("Host", "Content-Length", "Transfer-Encoding"):
            with self.subTest(header=name), self.assertRaises(runtime.PraiseError):
                runtime.perform_request(
                    eng, f"http://127.0.0.1:{self.port}/api/v1/ok", headers={name: "forbidden"},
                    role="scout", model=DS_FLASH,
                )
        self.assertEqual(self.httpd.hits, [])

    def test_candidate_bound_requests_cannot_skip_the_gate(self):
        _, eng = self._blackbox()
        candidate = self._new_source_candidate(eng)
        with self.assertRaises(runtime.PraiseError):
            runtime.perform_request(
                eng, f"http://127.0.0.1:{self.port}/api/v1/ok", candidate_id=candidate["id"],
                role="proof", model=DS_PRO,
            )
        self.assertEqual(self.httpd.hits, [])

    def test_response_capture_is_bounded(self):
        _, eng = self._blackbox()
        result = runtime.perform_request(
            eng, f"http://127.0.0.1:{self.port}/api/v1/large", role="scout", model=DS_FLASH,
        )
        self.assertTrue(result["truncated"])
        self.assertEqual(result["response_body"], "x" * runtime.MAX_RESPONSE_BYTES)

    def test_out_of_scope_url_rejected(self):
        _, eng = self._blackbox()
        with self.assertRaises(runtime.PraiseError):
            runtime.perform_request(
                eng, f"http://127.0.0.1:{self.port}/api/v1evil", role="scout", model=DS_FLASH
            )

    def test_source_mode_has_no_url_assets(self):
        _, eng = self._init_source()
        with self.assertRaises(runtime.PraiseError):
            runtime.perform_request(
                eng, f"http://127.0.0.1:{self.port}/api/v1/ok", role="scout", model=DS_FLASH
            )

    def test_disallowed_method_rejected(self):
        _, eng = self._blackbox()
        with self.assertRaises(runtime.PraiseError):
            runtime.perform_request(
                eng, f"http://127.0.0.1:{self.port}/api/v1/ok", method="POST", role="s", model=DS_FLASH
            )

    def test_redirect_not_followed(self):
        _, eng = self._blackbox()
        result = runtime.perform_request(
            eng, f"http://127.0.0.1:{self.port}/api/v1/redirect", role="scout", model=DS_FLASH
        )
        self.assertEqual(result["status_code"], 302)
        self.assertFalse(result["redirect_followed"])
        self.assertEqual(self.httpd.hits, ["/api/v1/redirect"])  # no follow to /outside

    def test_shared_request_budget(self):
        _, eng = self._blackbox(max_requests=2)
        runtime.perform_request(eng, f"http://127.0.0.1:{self.port}/api/v1/ok", role="s", model=DS_FLASH)
        runtime.perform_request(eng, f"http://127.0.0.1:{self.port}/api/v1/ok", role="s", model=DS_FLASH)
        with self.assertRaises(runtime.PraiseError) as ctx:
            runtime.perform_request(eng, f"http://127.0.0.1:{self.port}/api/v1/ok", role="s", model=DS_FLASH)
        self.assertIn("budget exhausted", str(ctx.exception))

    def test_throttle(self):
        _, eng = self._blackbox(max_requests=10, interval=3600)
        runtime.perform_request(eng, f"http://127.0.0.1:{self.port}/api/v1/ok", role="s", model=DS_FLASH)
        with self.assertRaises(runtime.PraiseError) as ctx:
            runtime.perform_request(eng, f"http://127.0.0.1:{self.port}/api/v1/ok", role="s", model=DS_FLASH)
        self.assertIn("throttle", str(ctx.exception))


class CLITests(RuntimeTestBase):
    def _run(self, argv):
        out = io.StringIO()
        err = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def _run_ok(self, argv):
        code, out, err = self._run(argv)
        self.assertEqual(code, 0, msg=f"expected success, stderr={err!r}")
        self.assertEqual(err, "")
        return json.loads(out)

    def _run_fail(self, argv):
        code, out, err = self._run(argv)
        self.assertNotEqual(code, 0)
        self.assertEqual(out, "")
        return json.loads(err)["error"]

    def test_end_to_end_flow(self):
        src = self._source_dir()
        eng = os.path.join(self.root, "eng")
        self._run_ok(
            ["init", "--directory", eng, "--program", "P", "--basis", "B", "--asset", src, "--mode", "source"]
        )

        self._write_evidence(eng, "e1.json", b"evidence-v1")
        finding = os.path.join(self.root, "finding.json")
        with open(finding, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "producer_model": DS_PRO,
                    "evidence": ["e1.json"],
                    "source_ref": "src/a.py:10",
                    "sink_ref": "src/b.py:20",
                },
                fh,
            )
        cand = self._run_ok(["--engagement", eng, "candidate", "--input", finding])
        cand_id = cand["id"]

        self._run_ok(["--engagement", eng, "gate", "--candidate", cand_id, "--decision", "pass", "--reason", "ok", "--model", MIMO])

        self._write_evidence(eng, "p1.json", b"proof-a")
        self._run_ok(["--engagement", eng, "reproduce", "--candidate", cand_id, "--run-id", "r1", "--clean-state", "clean-A", "--evidence", "p1.json", "--model", DS_PRO])
        self._write_evidence(eng, "p2.json", b"proof-b")
        self._run_ok(["--engagement", eng, "reproduce", "--candidate", cand_id, "--run-id", "r2", "--clean-state", "clean-B", "--evidence", "p2.json", "--model", DS_PRO])

        verdict = self._run_ok(["--engagement", eng, "verdict", "--candidate", cand_id, "--decision", "confirmed", "--reason", "twice", "--model", GLM])
        self.assertEqual(verdict["status"], "confirmed")

        shown = self._run_ok(["--engagement", eng, "show", "--candidate", cand_id])
        self.assertEqual(shown["candidate"]["status"], "confirmed")
        self.assertFalse(shown["candidate"]["report_ready"])
        self._write_evidence(eng, "review.json", b"independent final review of current proof pair")
        model = runtime.load_roles()["roles"][runtime.load_roles()["stages"]["review"]]["models"][0]
        reviewed = self._run_ok(["--engagement", eng, "review", "--candidate", cand_id,
                                 "--decision", "approved", "--reason", "current evidence", "--model", model,
                                 "--evidence", "review.json"])
        self.assertTrue(reviewed["report_ready"])

    def test_cli_dispatch_accepts_keyword_tier_packet_and_attempt(self):
        _, eng = self._init_source()
        candidate = self._new_source_candidate(eng)["id"]
        packet = DispatchTests._packet(self, eng, candidate)
        attempt = DispatchTests._attempt(self, eng, candidate)
        result = self._run_ok(["--engagement", eng, "dispatch", "--stage", "discover",
                              "--candidate", candidate, "--tier", "deep", "--reason", "missing branch",
                              "--packet", packet, "--attempt", str(attempt)])
        self.assertEqual(result["tier"], "deep")
        self.assertEqual(result["packet"]["ref"], packet)

    def test_cli_packet_writes_validated_content_addressed_artifact(self):
        _, eng = self._init_source()
        candidate = self._new_source_candidate(eng)["id"]
        packet_ref = DispatchTests._packet(self, eng, candidate)
        path = os.path.join(eng, "evidence", packet_ref)
        created = self._run_ok(["--engagement", eng, "packet", "--input", path, "--model", DS_FLASH])
        self.assertEqual(runtime.artifact(eng, created["ref"])["sha256"], created["sha256"])
        self.assertLessEqual(created["bytes"], 8192)

    def test_lead_recovery_cannot_use_another_engagement_or_non_primary_attempt(self):
        _, eng = self._init_source()
        _, sibling = self._init_source("sibling")
        model = runtime.load_roles()["lead_model"]
        lead = runtime.register_agent(sibling, "lead", "Lead", "lead", model)["agent"]
        self._write_evidence(sibling, "failure.json", b"observed model failure")
        data = {"status": "unresolved", "worker": "lead", "tier": "normal", "finding_id": None,
                "execution_failure": "model", "evidence": ["failure.json"]}
        attempt = runtime.send_message(sibling, lead, model, "@lead", "close", data, evidence=["failure.json"])["seq"]
        with patch.object(cli.os, "execvp") as execute:
            self._run_fail(["--engagement", eng, "lead", "--recover", str(attempt)])
            execute.assert_not_called()
        lead = runtime.register_agent(eng, "flash-lead", "Lead", "lead", DS_FLASH)["agent"]
        self._write_evidence(eng, "failure.json", b"Recovery model failure is not a primary Lead failure")
        attempt = runtime.send_message(eng, lead, DS_FLASH, "@lead", "close", data, evidence=["failure.json"])["seq"]
        with patch.object(cli.os, "execvp") as execute:
            self._run_fail(["--engagement", eng, "lead", "--recover", str(attempt)])
            execute.assert_not_called()

    def test_lead_denies_identity_and_scope_overrides(self):
        _, eng = self._init_source()
        for flag in ("--model=x", "--cwd", "--provider=x", "--thinking=low", "-mfoo"):
            with patch.object(cli.os, "execvp") as execute:
                self.assertIn("cannot override", self._run_fail(["--engagement", eng, "lead", "--", flag]))
                execute.assert_not_called()

    def test_lead_refuses_missing_or_unknown_catalog_identity(self):
        _, eng = self._init_source()
        for model in (None, "", "unrecognized/model", 123):
            with self.subTest(model=model):
                catalog = {**runtime.load_roles(), "lead_model": model}
                with patch.object(runtime, "load_roles", return_value=catalog), patch.object(cli.os, "execvp") as execute:
                    self.assertIn("known-family lead model", self._run_fail(["--engagement", eng, "lead"]))
                    execute.assert_not_called()

    def test_lead_recovery_is_explicit_durable_current_execution_failure(self):
        _, eng = self._init_source()
        catalog = runtime.load_roles()
        model = catalog["lead_model"]
        lead = runtime.register_agent(eng, "lead", "Lead", "lead", model)["agent"]
        self._write_evidence(eng, "failure.json", b"observed provider refusal; no finding judgment")
        data = {"status": "unresolved", "finding_id": None, "worker": "lead", "tier": "normal",
                "execution_failure": "refusal", "evidence": ["failure.json"]}
        attempt = runtime.send_message(eng, lead, model, "@lead", "close", data, evidence=["failure.json"])["seq"]
        with patch.object(cli.os, "execvp") as execute:
            self.assertEqual(self._run(["--engagement", eng, "lead", "--recover", str(attempt)])[0], 0)
        self.assertEqual(execute.call_args.args[1][-1], catalog["lead_recovery_model"])
        self._write_evidence(eng, "failure.json", b"changed")
        with patch.object(cli.os, "execvp") as execute:
            self.assertIn("changed", self._run_fail(["--engagement", eng, "lead", "--recover", str(attempt)]))
            execute.assert_not_called()

    def test_unavailable_native_launcher_remains_failure(self):
        _, eng = self._init_source()
        with patch.object(cli.os, "execvp", side_effect=FileNotFoundError("omp unavailable")) as execute:
            self.assertIn("launcher failed", self._run_fail(["--engagement", eng, "lead"]))
        self.assertEqual(execute.call_count, 1)

    def test_cli_error_is_json_and_nonzero(self):
        message = self._run_fail(["--engagement", os.path.join(self.root, "missing"), "show"])
        self.assertIn("not an engagement", message)

    def test_show_exposes_source_roots(self):
        src = self._source_dir()
        eng = os.path.join(self.root, "eng")
        self._run_ok(
            ["init", "--directory", eng, "--program", "P", "--basis", "B", "--asset", src, "--mode", "source"]
        )
        shown = self._run_ok(["--engagement", eng, "show"])
        self.assertEqual(len(shown["scope"]["source_roots"]), 1)
        self.assertEqual(shown["scope"]["url_assets"], [])


if __name__ == "__main__":
    unittest.main()
