"""Regression tests for praiseassistant.runtime and the praiseassistant CLI.

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
import tempfile
import threading
import unittest
from unittest.mock import patch

from praiseassistant import cli, policy, runtime

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
    def test_plan_dispatch_needs_no_candidate(self):
        _, eng = self._init_source()
        result = runtime.dispatch(eng, "plan")
        self.assertEqual(result["stage"], "plan")
        self.assertEqual(result["agent"], "pentest-planner")
        self.assertEqual(result["family"], "gpt")

    def test_proof_dispatch_requires_gated(self):
        _, eng = self._init_source()
        cand = self._new_source_candidate(eng)
        with self.assertRaises(runtime.PraiseError):
            runtime.dispatch(eng, "proof", candidate_id=cand["id"])
        runtime.gate_candidate(eng, cand["id"], "pass", "ok", MIMO)
        result = runtime.dispatch(eng, "proof", candidate_id=cand["id"])
        self.assertEqual(result["stage"], "proof")

    def test_verdict_dispatch_selects_different_family(self):
        _, eng = self._init_source()
        cand = self._new_source_candidate(eng, producer=DS_PRO)
        result = runtime.dispatch(eng, "verdict", candidate_id=cand["id"])
        self.assertNotEqual(result["family"], "deepseek")
        self.assertEqual(result["agent"], "pentest-skeptic")

    def test_verdict_dispatch_skips_producer_family(self):
        _, eng = self._init_source()
        cand = self._new_source_candidate(eng, producer=GLM)
        result = runtime.dispatch(eng, "verdict", candidate_id=cand["id"])
        self.assertNotEqual(result["family"], "glm")

    def test_dispatch_requires_candidate_for_verdict(self):
        _, eng = self._init_source()
        with self.assertRaises(runtime.PraiseError):
            runtime.dispatch(eng, "verdict")

    def test_dispatch_requires_an_attested_engagement(self):
        with self.assertRaises(runtime.PraiseError):
            runtime.dispatch(self.root, "plan")

    def test_escalation_requires_a_reason(self):
        _, eng = self._init_source()
        with self.assertRaises(runtime.PraiseError):
            runtime.dispatch(eng, "discover", escalated=True)
        result = runtime.dispatch(eng, "discover", escalated=True, reason="cross-file trace unresolved")
        self.assertEqual(result["agent"], "pentest-finder-deep")


class ChatTests(RuntimeTestBase):
    def test_chat_requires_ask_or_close(self):
        _, eng = self._init_source()
        with self.assertRaises(runtime.PraiseError):
            runtime.record_event(eng, "lead", GPT, "no ask or close")
        with self.assertRaises(runtime.PraiseError):
            runtime.record_event(eng, "lead", GPT, "both", ask="a", close="c")

    def test_concurrent_chat_has_one_ordered_entry_per_committed_event(self):
        _, eng = self._init_source()
        with ThreadPoolExecutor(max_workers=8) as workers:
            events = list(workers.map(
                lambda index: runtime.record_event(
                    eng, "scout", DS_FLASH, f"event-{index}\n### forged-entry", close="fixture completed"
                ),
                range(16),
            ))
        with open(os.path.join(eng, "agentschat.md"), encoding="utf-8") as fh:
            headers = [line for line in fh if line.startswith("### ")]
        sequences = [int(line.rsplit("seq=", 1)[1]) for line in headers]
        self.assertEqual(sequences, sorted(event["seq"] for event in events))
        self.assertTrue(all("| eng |" in header for header in headers))
        conn = runtime.connect(eng)
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 16)
        finally:
            conn.close()

    def test_chat_identity_cannot_forge_an_entry(self):
        _, eng = self._init_source()
        with self.assertRaises(runtime.PraiseError):
            runtime.record_event(eng, "scout\n### forged", DS_FLASH, "summary", close="done")


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
