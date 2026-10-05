"""Regression tests for praiseassistant.learning.

The learning commands delegate path/schema/family concerns to
``praiseassistant.runtime``. These tests pin learning's own contract by
substituting deterministic doubles for the runtime helpers, so they stay
decoupled from the runtime's internal schema while still exercising the exact
helper signatures the contract promises:

- connect(directory) -> sqlite3.Connection
- get_candidate(directory, id) -> dict | None
- model_family(model) -> str | None
- artifact(directory, ref) -> {"path", "sha256"} (raises on missing/traversal)
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import sqlite3
import tempfile
import threading
import types
import unittest

from praiseassistant import learning


class LearningTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.directory = self._tmp.name
        self.db_path = os.path.join(self.directory, "state.sqlite3")
        os.makedirs(os.path.join(self.directory, "evidence"), exist_ok=True)

        self._candidates = {
            "C1": {"status": "confirmed", "producer_models": ["model:deepseek-pro"]},
            "C2": {"status": "gated", "producer_models": ["model:deepseek-pro"]},
            "C3": {"status": "rejected", "producer_models": ["model:deepseek-pro"]},
        }

        # Patch runtime helpers with deterministic doubles.
        self._original = {
            "connect": learning.connect,
            "get_candidate": learning.get_candidate,
            "model_family": learning.model_family,
            "artifact": learning.artifact,
        }
        learning.connect = self._fake_connect
        learning.get_candidate = self._fake_get_candidate
        learning.model_family = self._fake_model_family
        learning.artifact = self._fake_artifact

    def tearDown(self):
        learning.connect = self._original["connect"]
        learning.get_candidate = self._original["get_candidate"]
        learning.model_family = self._original["model_family"]
        learning.artifact = self._original["artifact"]
        self._tmp.cleanup()

    # --- runtime doubles -------------------------------------------------

    def _fake_connect(self, directory):
        return sqlite3.connect(os.path.join(directory, "state.sqlite3"))

    def _fake_get_candidate(self, directory, candidate_id):
        return self._candidates.get(candidate_id)

    @staticmethod
    def _fake_model_family(model):
        families = {
            "model:deepseek-pro": "deepseek",
            "model:deepseek-flash": "deepseek",
            "model:glm-flash": "glm",
            "model:grok": "grok",
        }
        return families.get(model)

    @staticmethod
    def _fake_artifact(directory, ref):
        base = os.path.realpath(os.path.join(directory, "evidence"))
        resolved = os.path.realpath(os.path.join(base, ref))
        if resolved != base and not resolved.startswith(base + os.sep):
            raise ValueError("evidence reference escapes the evidence directory")
        if not os.path.isfile(resolved):
            raise FileNotFoundError(ref)
        with open(resolved, "rb") as fh:
            return {"path": resolved, "sha256": hashlib.sha256(fh.read()).hexdigest()}

    # --- helpers ---------------------------------------------------------

    def _write_evidence(self, ref, content):
        path = os.path.join(self.directory, "evidence", ref)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(content)
        return path

    @staticmethod
    def _sha256(content):
        return hashlib.sha256(content).hexdigest()

    def _invoke(self, command, **kwargs):
        args = types.SimpleNamespace(
            engagement=self.directory, learn_command=command, **kwargs
        )
        out = io.StringIO()
        err = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = learning.run(args)
        return code, out.getvalue(), err.getvalue()

    def _invoke_ok(self, command, **kwargs):
        code, out, err = self._invoke(command, **kwargs)
        self.assertEqual(code, 0, msg=f"expected success, stderr={err!r}")
        self.assertEqual(err, "")
        return json.loads(out)

    def _invoke_fail(self, command, **kwargs):
        code, out, err = self._invoke(command, **kwargs)
        self.assertNotEqual(code, 0)
        self.assertEqual(out, "")
        payload = json.loads(err)
        self.assertIn("error", payload)
        return payload["error"]

    def _query(self, sql, params=()):
        conn = sqlite3.connect(self.db_path)
        try:
            return conn.execute(sql, params).fetchall()
        finally:
            conn.close()

    def _observe(self, candidate="C1", evidence="e1.json", model="model:deepseek-pro", summary="lesson text"):
        self._write_evidence(evidence, b"evidence-v1")
        return self._invoke_ok(
            "observe", candidate=candidate, evidence=evidence, model=model, summary=summary
        )

    def _evaluate_passing(self, lesson_id, c1="c1.json", c2="c2.json"):
        self._write_evidence(c1, b"case-one")
        self._write_evidence(c2, b"case-two")
        input_path = os.path.join(self.directory, "cases-pass.json")
        with open(input_path, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "cases": [
                        {"id": "A", "expected": True, "baseline": False, "learned": True, "evidence": c1},
                        {"id": "B", "expected": False, "baseline": False, "learned": False, "evidence": c2},
                    ]
                },
                fh,
            )
        return self._invoke_ok("evaluate", lesson=lesson_id, input=input_path)


class ObserveTests(LearningTestBase):
    def test_observe_records_provenance_and_hash(self):
        result = self._observe()
        self.assertTrue(result["lesson_id"].startswith("L"))
        self.assertEqual(result["status"], "proposed")
        self.assertEqual(result["candidate_id"], "C1")
        self.assertEqual(result["producer_model"], "model:deepseek-pro")
        self.assertEqual(result["producer_family"], "deepseek")
        self.assertEqual(result["evidence_sha256"], self._sha256(b"evidence-v1"))

        rows = self._query("SELECT id, summary, status, active FROM lessons")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1], "lesson text")
        self.assertEqual(rows[0][2], "proposed")
        self.assertEqual(rows[0][3], 1)

    def test_observe_rejects_unclosed_candidate(self):
        self._write_evidence("e1.json", b"evidence-v1")
        message = self._invoke_fail(
            "observe", candidate="C2", evidence="e1.json",
            model="model:deepseek-pro", summary="lesson text",
        )
        self.assertIn("not a closed case", message)

    def test_observe_rejects_missing_candidate(self):
        self._write_evidence("e1.json", b"evidence-v1")
        message = self._invoke_fail(
            "observe", candidate="NOPE", evidence="e1.json",
            model="model:deepseek-pro", summary="lesson text",
        )
        self.assertIn("candidate not found", message)

    def test_observe_rejects_missing_evidence(self):
        message = self._invoke_fail(
            "observe", candidate="C1", evidence="absent.json",
            model="model:deepseek-pro", summary="lesson text",
        )
        self.assertIn("not available", message)

    def test_observe_rejects_spoofed_evidence_escape(self):
        message = self._invoke_fail(
            "observe", candidate="C1", evidence="../escape.json",
            model="model:deepseek-pro", summary="lesson text",
        )
        self.assertIn("not available", message)

    def test_observe_rejects_evidence_outside_dir(self):
        outside = os.path.join(self.directory, "outside.txt")
        with open(outside, "w", encoding="utf-8") as fh:
            fh.write("outside")
        message = self._invoke_fail(
            "observe", candidate="C1", evidence="../outside.txt",
            model="model:deepseek-pro", summary="lesson text",
        )
        self.assertIn("not available", message)

    def test_observe_rejects_oversized_summary(self):
        self._write_evidence("e1.json", b"evidence-v1")
        message = self._invoke_fail(
            "observe", candidate="C1", evidence="e1.json",
            model="model:deepseek-pro", summary="x" * (learning.MAX_SUMMARY_CHARS + 1),
        )
        self.assertIn("summary exceeds", message)

    def test_observe_handles_get_candidate_raising(self):
        self._write_evidence("e1.json", b"evidence-v1")
        original = learning.get_candidate

        def raising(directory, candidate_id):
            raise KeyError(candidate_id)

        learning.get_candidate = raising
        try:
            message = self._invoke_fail(
                "observe", candidate="C1", evidence="e1.json",
                model="model:deepseek-pro", summary="lesson text",
            )
            self.assertIn("candidate not found", message)
        finally:
            learning.get_candidate = original


class EvaluateTests(LearningTestBase):
    def test_evaluate_passes_strict_improvement(self):
        lesson = self._observe()
        result = self._evaluate_passing(lesson["lesson_id"])
        self.assertTrue(result["passed"])
        self.assertEqual(result["baseline_correct"], 1)
        self.assertEqual(result["learned_correct"], 2)
        self.assertEqual(result["baseline_total"], 2)
        self.assertEqual(result["learned_total"], 2)
        self.assertEqual(result["evidence_sha256"]["c1.json"], self._sha256(b"case-one"))

    def test_evaluate_requires_both_controls(self):
        lesson = self._observe()
        self._write_evidence("c1.json", b"case-one")
        input_path = os.path.join(self.directory, "cases.json")
        with open(input_path, "w", encoding="utf-8") as fh:
            json.dump(
                {"cases": [
                    {"id": "A", "expected": True, "baseline": False, "learned": True, "evidence": "c1.json"},
                    {"id": "B", "expected": True, "baseline": True, "learned": True, "evidence": "c1.json"},
                ]},
                fh,
            )
        message = self._invoke_fail("evaluate", lesson=lesson["lesson_id"], input=input_path)
        self.assertIn("positive and negative controls", message)

    def test_evaluate_rejects_duplicate_case_ids(self):
        lesson = self._observe()
        self._write_evidence("c1.json", b"case-one")
        self._write_evidence("c2.json", b"case-two")
        input_path = os.path.join(self.directory, "cases.json")
        with open(input_path, "w", encoding="utf-8") as fh:
            json.dump(
                {"cases": [
                    {"id": "A", "expected": True, "baseline": False, "learned": True, "evidence": "c1.json"},
                    {"id": "A", "expected": False, "baseline": False, "learned": False, "evidence": "c2.json"},
                ]},
                fh,
            )
        message = self._invoke_fail("evaluate", lesson=lesson["lesson_id"], input=input_path)
        self.assertIn("duplicate case id", message)

    def test_evaluate_rejects_missing_case_evidence(self):
        lesson = self._observe()
        self._write_evidence("c1.json", b"case-one")
        input_path = os.path.join(self.directory, "cases.json")
        with open(input_path, "w", encoding="utf-8") as fh:
            json.dump(
                {"cases": [
                    {"id": "A", "expected": True, "baseline": False, "learned": True, "evidence": "c1.json"},
                    {"id": "B", "expected": False, "baseline": False, "learned": False, "evidence": "missing.json"},
                ]},
                fh,
            )
        message = self._invoke_fail("evaluate", lesson=lesson["lesson_id"], input=input_path)
        self.assertIn("not available", message)

    def test_evaluate_flags_introduced_miss_and_false_positive(self):
        lesson = self._observe()
        self._write_evidence("c1.json", b"case-one")
        self._write_evidence("c2.json", b"case-two")
        input_path = os.path.join(self.directory, "cases.json")
        with open(input_path, "w", encoding="utf-8") as fh:
            json.dump(
                {"cases": [
                    {"id": "A", "expected": True, "baseline": True, "learned": False, "evidence": "c1.json"},
                    {"id": "B", "expected": False, "baseline": False, "learned": True, "evidence": "c2.json"},
                ]},
                fh,
            )
        result = self._invoke_ok("evaluate", lesson=lesson["lesson_id"], input=input_path)
        self.assertFalse(result["passed"])
        self.assertEqual(result["baseline_correct"], 2)
        self.assertEqual(result["learned_correct"], 0)

    def test_evaluate_requires_strict_improvement(self):
        lesson = self._observe()
        self._write_evidence("c1.json", b"case-one")
        self._write_evidence("c2.json", b"case-two")
        input_path = os.path.join(self.directory, "cases.json")
        with open(input_path, "w", encoding="utf-8") as fh:
            json.dump(
                {"cases": [
                    {"id": "A", "expected": True, "baseline": True, "learned": True, "evidence": "c1.json"},
                    {"id": "B", "expected": False, "baseline": False, "learned": False, "evidence": "c2.json"},
                ]},
                fh,
            )
        result = self._invoke_ok("evaluate", lesson=lesson["lesson_id"], input=input_path)
        self.assertFalse(result["passed"])


class PromoteTests(LearningTestBase):
    def _approve(self, lesson_id, reviewer="model:glm-flash"):
        return self._invoke_ok(
            "promote", lesson=lesson_id, reviewer_model=reviewer, reason="independent approval"
        )

    def test_promote_rejects_same_family_reviewer(self):
        lesson = self._observe(model="model:deepseek-pro")
        self._evaluate_passing(lesson["lesson_id"])
        message = self._invoke_fail(
            "promote", lesson=lesson["lesson_id"],
            reviewer_model="model:deepseek-flash", reason="same family",
        )
        self.assertIn("different model family", message)

    def test_promote_rejects_unknown_reviewer_family(self):
        lesson = self._observe(model="model:deepseek-pro")
        self._evaluate_passing(lesson["lesson_id"])
        message = self._invoke_fail(
            "promote", lesson=lesson["lesson_id"],
            reviewer_model="model:unknown", reason="unknown reviewer",
        )
        self.assertIn("unknown", message)

    def test_promote_requires_passed_evaluation(self):
        lesson = self._observe(model="model:deepseek-pro")
        message = self._invoke_fail(
            "promote", lesson=lesson["lesson_id"],
            reviewer_model="model:glm-flash", reason="no evaluation",
        )
        self.assertIn("no paired evaluation", message)

    def test_promote_rejects_failed_evaluation(self):
        lesson = self._observe(model="model:deepseek-pro")
        self._write_evidence("c1.json", b"case-one")
        self._write_evidence("c2.json", b"case-two")
        input_path = os.path.join(self.directory, "cases.json")
        with open(input_path, "w", encoding="utf-8") as fh:
            json.dump(
                {"cases": [
                    {"id": "A", "expected": True, "baseline": True, "learned": False, "evidence": "c1.json"},
                    {"id": "B", "expected": False, "baseline": False, "learned": False, "evidence": "c2.json"},
                ]},
                fh,
            )
        self._invoke_ok("evaluate", lesson=lesson["lesson_id"], input=input_path)
        message = self._invoke_fail(
            "promote", lesson=lesson["lesson_id"],
            reviewer_model="model:glm-flash", reason="failed eval",
        )
        self.assertIn("did not pass", message)

    def test_promote_rejects_changed_lesson_evidence(self):
        lesson = self._observe(model="model:deepseek-pro")
        self._evaluate_passing(lesson["lesson_id"])
        self._write_evidence("e1.json", b"tampered-after-observe")
        message = self._invoke_fail(
            "promote", lesson=lesson["lesson_id"],
            reviewer_model="model:glm-flash", reason="approval",
        )
        self.assertIn("changed since observe", message)

    def test_promote_rejects_changed_evaluation_evidence(self):
        lesson = self._observe(model="model:deepseek-pro")
        self._evaluate_passing(lesson["lesson_id"])
        self._write_evidence("c1.json", b"tampered-case-evidence")
        message = self._invoke_fail(
            "promote", lesson=lesson["lesson_id"],
            reviewer_model="model:glm-flash", reason="approval",
        )
        self.assertIn("changed since evaluate", message)

    def test_promote_succeeds_and_updates_record(self):
        lesson = self._observe(model="model:deepseek-pro")
        self._evaluate_passing(lesson["lesson_id"])
        result = self._approve(lesson["lesson_id"], reviewer="model:glm-flash")
        self.assertEqual(result["status"], "approved")
        self.assertEqual(result["reviewer_model"], "model:glm-flash")
        self.assertEqual(result["reviewer_family"], "glm")

        rows = self._query(
            "SELECT status, active, reviewer_model, reviewer_family, promotion_reason FROM lessons WHERE id = ?",
            (lesson["lesson_id"],),
        )
        self.assertEqual(rows[0][0], "approved")
        self.assertEqual(rows[0][1], 1)
        self.assertEqual(rows[0][2], "model:glm-flash")
        self.assertEqual(rows[0][3], "glm")
        self.assertEqual(rows[0][4], "independent approval")


class RollbackTests(LearningTestBase):
    def test_rollback_deactivates_but_preserves_history(self):
        lesson = self._observe(model="model:deepseek-pro")
        self._evaluate_passing(lesson["lesson_id"])
        self._invoke_ok(
            "promote", lesson=lesson["lesson_id"],
            reviewer_model="model:glm-flash", reason="approval",
        )

        result = self._invoke_ok("rollback", lesson=lesson["lesson_id"], reason="regressed")
        self.assertEqual(result["status"], "rolled_back")

        row = self._query(
            "SELECT status, active, rollback_reason, summary FROM lessons WHERE id = ?",
            (lesson["lesson_id"],),
        )[0]
        self.assertEqual(row[0], "rolled_back")
        self.assertEqual(row[1], 0)
        self.assertEqual(row[2], "regressed")
        self.assertEqual(row[3], "lesson text")  # history preserved

        # Approved retrieval must exclude a rolled-back lesson.
        listed = self._invoke_ok("list", approved=True)
        self.assertEqual(listed["lessons"], [])
        # Full history still shows it, deactivated.
        full = self._invoke_ok("list")
        self.assertEqual(len(full["lessons"]), 1)
        self.assertFalse(full["lessons"][0]["active"])
        self.assertEqual(full["lessons"][0]["status"], "rolled_back")

    def test_rollback_missing_lesson(self):
        message = self._invoke_fail("rollback", lesson="L-missing", reason="nope")
        self.assertIn("lesson not found", message)

    def test_rollback_twice_fails_closed(self):
        lesson = self._observe()
        self._invoke_ok("rollback", lesson=lesson["lesson_id"], reason="first")
        message = self._invoke_fail("rollback", lesson=lesson["lesson_id"], reason="second")
        self.assertIn("already rolled back", message)

    def test_promote_cannot_resurrect_rolled_back_lesson(self):
        lesson = self._observe(model="model:deepseek-pro")
        self._evaluate_passing(lesson["lesson_id"])
        self._invoke_ok(
            "promote", lesson=lesson["lesson_id"],
            reviewer_model="model:glm-flash", reason="first approval",
        )
        self._invoke_ok("rollback", lesson=lesson["lesson_id"], reason="retire")

        message = self._invoke_fail(
            "promote", lesson=lesson["lesson_id"],
            reviewer_model="model:glm-flash", reason="late approval",
        )
        self.assertIn("rolled back", message)

        row = self._query(
            "SELECT active, status FROM lessons WHERE id = ?", (lesson["lesson_id"],)
        )[0]
        self.assertEqual(row[0], 0)
        self.assertEqual(row[1], "rolled_back")


class ConcurrencyTests(LearningTestBase):
    def test_concurrent_promote_and_rollback_never_resurrects(self):
        # Two threads drive the real handlers against the same SQLite file via
        # independent connections. The barrier overlaps the two write
        # transactions; BEGIN IMMEDIATE serializes them so the final state is
        # always rolled back -- never resurrected by a stale promote.
        lesson = self._observe(model="model:deepseek-pro")
        self._evaluate_passing(lesson["lesson_id"])

        barrier = threading.Barrier(2)
        outcomes = {}

        def do_promote():
            barrier.wait()
            args = types.SimpleNamespace(
                lesson=lesson["lesson_id"], reviewer_model="model:glm-flash", reason="race"
            )
            try:
                learning._run_promote(self.directory, args)
                outcomes["promote"] = "ok"
            except learning.LearningError as exc:
                outcomes["promote"] = str(exc)

        def do_rollback():
            barrier.wait()
            args = types.SimpleNamespace(lesson=lesson["lesson_id"], reason="race")
            try:
                learning._run_rollback(self.directory, args)
                outcomes["rollback"] = "ok"
            except learning.LearningError as exc:
                outcomes["rollback"] = str(exc)

        threads = [threading.Thread(target=do_promote), threading.Thread(target=do_rollback)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(outcomes["rollback"], "ok")
        row = self._query(
            "SELECT active, status FROM lessons WHERE id = ?", (lesson["lesson_id"],)
        )[0]
        self.assertEqual(row[0], 0)
        self.assertEqual(row[1], "rolled_back")


class ListTests(LearningTestBase):
    def test_list_approved_filters_and_is_data_only(self):
        lesson = self._observe(model="model:deepseek-pro", summary="approved lesson")
        self._evaluate_passing(lesson["lesson_id"])
        self._invoke_ok(
            "promote", lesson=lesson["lesson_id"],
            reviewer_model="model:glm-flash", reason="approval",
        )
        # A second, unapproved proposal must not appear in --approved.
        self._write_evidence("e2.json", b"evidence-v2")
        self._invoke_ok(
            "observe", candidate="C3", evidence="e2.json",
            model="model:deepseek-pro", summary="pending lesson",
        )

        approved = self._invoke_ok("list", approved=True)
        self.assertEqual(len(approved["lessons"]), 1)
        record = approved["lessons"][0]
        self.assertEqual(record["id"], lesson["lesson_id"])
        self.assertEqual(record["status"], "approved")
        self.assertTrue(record["active"])
        self.assertTrue(record["evaluation"]["passed"])

    def test_concurrent_lessons_and_evaluations_are_not_erased(self):
        first = self._observe(candidate="C1", evidence="e1.json", summary="first")
        self._write_evidence("e2.json", b"evidence-v2")
        second = self._invoke_ok(
            "observe", candidate="C3", evidence="e2.json",
            model="model:deepseek-pro", summary="second",
        )
        self.assertNotEqual(first["lesson_id"], second["lesson_id"])
        self.assertEqual(len(self._query("SELECT id FROM lessons")), 2)

        self._evaluate_passing(first["lesson_id"], c1="c1.json", c2="c2.json")
        self._evaluate_passing(first["lesson_id"], c1="c3.json", c2="c4.json")
        evaluations = self._query(
            "SELECT lesson_id FROM lesson_evaluations WHERE lesson_id = ?",
            (first["lesson_id"],),
        )
        self.assertEqual(len(evaluations), 2)


class ParserTests(LearningTestBase):
    def test_configure_parser_and_run_end_to_end(self):
        self._write_evidence("e1.json", b"evidence-v1")
        parser = argparse.ArgumentParser(prog="praiseassistant")
        parser.add_argument("--engagement", default=None)
        subparsers = parser.add_subparsers(dest="command", required=True)
        learning.configure_parser(subparsers)

        args = parser.parse_args(
            [
                "--engagement", self.directory,
                "learn", "observe",
                "--candidate", "C1",
                "--summary", "lesson via cli",
                "--model", "model:deepseek-pro",
                "--evidence", "e1.json",
            ]
        )
        self.assertEqual(args.command, "learn")
        self.assertEqual(args.learn_command, "observe")

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = learning.run(args)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())["status"], "proposed")


if __name__ == "__main__":
    unittest.main()
