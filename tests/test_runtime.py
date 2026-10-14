"""Consumer-visible coordination regressions; no provider or target requests."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from praise import PraiseError, ROLE_NAMES, runtime

MODEL = "synthetic/worker:high"


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.eng = self.engagement("eng")

    def engagement(self, name):
        path = self.root / name
        runtime.init_engagement(path, program="owned fixture", basis="local test authorization",
                                assets=[str(self.source)])
        return path

    def agent(self, name, role="finder", *, directory=None, parent=None, observed=False):
        return runtime.register_agent(directory or self.eng, name, name, role, MODEL,
                                      parent=parent, observed=observed)["agent"]

    def send(self, sender, to, data=None, *, kind="ask", directory=None, **kwargs):
        return runtime.send_message(directory or self.eng, sender, MODEL, to, kind,
                                    {} if data is None else data, **kwargs)

    def evidence(self, ref="trace.json", content=b'{"source":"owned"}'):
        path = self.eng / "evidence" / ref
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def test_scope_initialization_and_compact_state(self):
        scope = runtime.load_scope(self.eng)
        self.assertEqual(scope["source_roots"], [str(self.source)])
        self.assertEqual(scope["max_requests"], 0)
        self.assertEqual(scope["allowed_methods"], ["GET"])
        lead = self.agent("lead", "lead", observed=True)
        state = runtime.show(self.eng)
        self.assertEqual(set(state), {"scope", "participants", "more"})
        self.assertEqual(state["participants"][0]["id"], lead)
        self.assertEqual(state["participants"][0]["model_source"], "host")
        with self.assertRaises(PraiseError):
            runtime.init_engagement(self.eng, program="replacement", basis="replacement", assets=[str(self.source)])
        self.assertEqual(runtime.load_scope(self.eng), scope)
        with self.assertRaises(PraiseError):
            runtime.init_engagement(self.root / "bad", program="", basis="owned", assets=[str(self.source)])
        self.assertFalse((self.root / "bad").exists())

    def test_all_fixed_role_topics_deliver_only_to_that_role(self):
        self.assertEqual(set(ROLE_NAMES), {"lead", "planner", "scout", "finder", "verifier",
                                          "exploiter", "skeptic", "reviewer", "tester"})
        agents = {role: self.agent(role, role) for role in ROLE_NAMES}
        sender = agents["lead"]
        sent = {role: self.send(sender, f"@{role}", {"role": role})["seq"] for role in ROLE_NAMES}
        for role, agent in agents.items():
            page = runtime.inbox(self.eng, agent)
            self.assertEqual([m["seq"] for m in page["messages"]], [sent[role]])
            self.assertEqual(page["messages"][0]["data"], {"role": role})
        for topic in ("@discover", "@proof", "@learning", "@archive", "@everyone"):
            with self.assertRaises(PraiseError):
                self.send(sender, topic)
        with self.assertRaises(PraiseError):
            self.agent("stage", "discover")

    def test_direct_replies_enforce_original_receiver_and_sender(self):
        sender, receiver, outsider = (self.agent(name) for name in ("sender", "receiver", "outsider"))
        asked = self.send(sender, receiver, {"need": "trace"})
        self.assertEqual(runtime.inbox(self.eng, outsider)["messages"], [])
        with self.assertRaises(PraiseError):
            self.send(outsider, sender, kind="reply", reply_to=asked["seq"])
        with self.assertRaises(PraiseError):
            self.send(receiver, outsider, kind="reply", reply_to=asked["seq"])
        with self.assertRaises(PraiseError):
            self.send(receiver, sender, kind="reply")
        replied = self.send(receiver, sender, {"answer": True}, kind="reply", reply_to=asked["seq"])
        message = runtime.inbox(self.eng, sender)["messages"][0]
        self.assertEqual((message["seq"], message["reply"]), (replied["seq"], asked["seq"]))
        topic = self.send(sender, "@verifier")
        verifier = self.agent("verifier", "verifier")
        self.send(verifier, sender, kind="reply", reply_to=topic["seq"])
        with self.assertRaises(PraiseError):
            self.send(outsider, sender, kind="reply", reply_to=topic["seq"])

    def test_engagement_isolation_includes_parents_agents_and_evidence(self):
        sibling = self.engagement("sibling")
        here = self.agent("same", "lead")
        there = self.agent("same", "lead", directory=sibling)
        self.assertNotEqual(here, there)
        self.send(here, "@lead", {"owned": True})
        self.assertEqual(runtime.inbox(sibling, there)["messages"], [])
        for action in (
            lambda: self.send(here, there),
            lambda: self.send(there, here),
            lambda: runtime.inbox(self.eng, there),
            lambda: self.agent("child", parent=there),
            lambda: self.agent("child", directory=sibling, parent=here),
        ):
            with self.assertRaises(PraiseError):
                action()
        foreign = sibling / "evidence" / "foreign.json"
        foreign.write_text("owned sibling", encoding="utf-8")
        with self.assertRaises(PraiseError):
            self.send(here, here, evidence=[str(foreign)])

    def test_parent_started_is_atomic_idempotent_and_preserves_provenance(self):
        parent = self.agent("parent", "lead", observed=True)
        child = runtime.register_agent(self.eng, "child", "child", "finder", MODEL,
                                       parent=parent, observed=True)
        self.assertEqual(child["parent"], parent)
        self.assertEqual(child["model"], MODEL)
        self.assertEqual(child["model_source"], "host")
        self.assertEqual(len(child["_messages"]), 1)
        event = runtime.inbox(self.eng, parent)["messages"][0]
        self.assertEqual(event["kind"], "event")
        self.assertEqual(event["from"], child["agent"])
        self.assertEqual(event["data"]["event"], "agent.started")
        self.assertEqual(event["data"]["model_source"], "host")
        repeated = runtime.register_agent(self.eng, "child", "child", "finder", MODEL,
                                          parent=parent, observed=True)
        self.assertEqual(repeated["agent"], child["agent"])
        self.assertEqual(repeated["_messages"], [])
        self.assertEqual(len(runtime.inbox(self.eng, parent)["messages"]), 1)
        asserted = self.agent("manual")
        roster = {row["id"]: row for row in runtime.peers(self.eng)["agents"]}
        self.assertEqual(roster[asserted]["model_source"], "asserted")
        self.assertEqual(roster[child["agent"]]["parent"], parent)
        with patch.object(runtime, "_emit_message", side_effect=OSError("fixture write failure")):
            with self.assertRaises(OSError):
                self.agent("rolled-back", parent=parent)
        self.assertNotIn("rolled-back", [row["name"] for row in runtime.peers(self.eng)["agents"]])

    def test_registration_identity_and_model_source_are_immutable(self):
        parent = self.agent("parent", "lead")
        other = self.agent("other", "lead")
        self.agent("child", parent=parent, observed=True)
        for name, role, model, lineage, observed in (
            ("changed", "finder", MODEL, parent, True),
            ("child", "scout", MODEL, parent, True),
            ("child", "finder", "synthetic/different", parent, True),
            ("child", "finder", MODEL, other, True),
            ("child", "finder", MODEL, None, True),
            ("child", "finder", MODEL, parent, False),
        ):
            with self.assertRaises(PraiseError):
                runtime.register_agent(self.eng, "child", name, role, model, parent=lineage, observed=observed)
        with self.assertRaises(PraiseError):
            runtime.register_agent(self.eng, "bad", "bad", "finder", MODEL, observed="host")

    def test_generic_close_is_not_a_workflow_report_or_implicit_completion(self):
        parent = self.agent("parent", "lead")
        child = self.agent("child", parent=parent)
        sent = self.send(child, parent, {"status": "finished", "result": {"count": 3}}, kind="close")
        self.assertEqual(len(sent["_messages"]), 1)
        messages = runtime.inbox(self.eng, parent)["messages"]
        self.assertEqual([m["kind"] for m in messages], ["event", "close"])
        self.assertEqual(messages[-1]["data"]["status"], "finished")
        # The adapter can send its own durable completion notification without special APIs.
        self.send(child, parent, {"event": "agent.completed", "status": "success"},
                  kind="close", key="host-completion")
        self.assertEqual(runtime.inbox(self.eng, parent)["messages"][-1]["data"]["event"], "agent.completed")

    def test_idempotency_binds_content_recipient_reply_and_artifact_hash(self):
        sender, receiver = self.agent("sender"), self.agent("receiver")
        path = self.evidence()
        first = self.send(sender, receiver, {"need": "trace"}, evidence=["trace.json"], key="call-1")
        repeat = self.send(sender, receiver, {"need": "trace"}, evidence=["trace.json"], key="call-1")
        self.assertEqual(first["seq"], repeat["seq"])
        self.assertTrue(repeat["duplicate"])
        self.assertEqual(repeat["_messages"], [])
        for recipient, data in ((receiver, {"need": "changed"}), (sender, {"need": "trace"})):
            with self.assertRaises(PraiseError):
                self.send(sender, recipient, data, evidence=["trace.json"], key="call-1")
        conn = runtime.connect(self.eng)
        try:
            anchors = json.loads(conn.execute("SELECT evidence_json FROM messages WHERE seq=?", (first["seq"],)).fetchone()[0])
            self.assertEqual(anchors, [{"ref": "trace.json", "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}])
        finally:
            conn.close()
        path.write_bytes(b"changed evidence")
        with self.assertRaises(PraiseError):
            self.send(sender, receiver, {"need": "trace"}, evidence=["trace.json"], key="call-1")
        self.assertEqual([m["seq"] for m in runtime.inbox(self.eng, receiver)["messages"]], [first["seq"]])

    def test_message_and_evidence_bounds_fail_before_commit(self):
        sender = self.agent("sender")
        for kind, data, model, target in (
            ("event", {}, MODEL, "@lead"),
            ("ask", {"text": "界" * 700}, MODEL, "@lead"),
            ("ask", {"number": float("nan")}, MODEL, "@lead"),
            ("ask", {}, "synthetic/forged", "@lead"),
            ("ask", {}, MODEL, "a9999"),
            ("ask", [], MODEL, "@lead"),
        ):
            with self.assertRaises(PraiseError):
                runtime.send_message(self.eng, sender, model, target, kind, data)
        for refs in (["missing"], ["../scope.json"], ["trace.json"] * 9, "trace.json"):
            with self.assertRaises(PraiseError):
                self.send(sender, sender, evidence=refs)
        with self.assertRaises(PraiseError):
            self.agent("forged\n### entry")
        external = self.root / "outside"
        external.write_text("owned fixture", encoding="utf-8")
        (self.eng / "evidence" / "link").symlink_to(external)
        with self.assertRaises(PraiseError):
            runtime.artifact(self.eng, "link")
        self.assertEqual(runtime.inbox(self.eng, sender)["messages"], [])

    def test_evidence_directory_symlink_cannot_cross_engagement(self):
        sibling = self.engagement("sibling")
        (sibling / "evidence" / "trace.json").write_text('{"private":"sibling"}')
        (self.eng / "evidence").rmdir()
        (self.eng / "evidence").symlink_to(sibling / "evidence", target_is_directory=True)
        with self.assertRaises(PraiseError):
            runtime.artifact(self.eng, "trace.json")

    def test_pagination_byte_caps_cursor_recovery_and_unrelated_messages(self):
        sender, receiver, other = (self.agent(name) for name in ("sender", "receiver", "other"))
        expected = []
        for index in range(40):
            expected.append(self.send(sender, receiver, {"index": index, "text": "x" * 1900})["seq"])
            self.send(sender, other, {"index": index})
        cursor, received = 0, []
        while True:
            page = runtime.inbox(self.eng, receiver, cursor, 7)
            self.assertLessEqual(len(json.dumps(page, ensure_ascii=False, separators=(",", ":")).encode()), runtime.MAX_INBOX_BYTES)
            received.extend(m["seq"] for m in page["messages"])
            cursor = page["cursor"]
            if not page["more"]:
                break
        self.assertEqual(received, expected)
        self.assertEqual(runtime.inbox(self.eng, receiver, cursor)["messages"], [])
        self.assertEqual(runtime.inbox(self.eng, receiver, 0, 1)["messages"][0]["seq"], expected[0])
        for after, limit in ((-1, 1), (True, 1), (2**63, 1), (0, 0), (0, 33)):
            with self.assertRaises(PraiseError):
                runtime.inbox(self.eng, receiver, after, limit)

    def test_snapshot_prevents_skipping_commit_between_empty_page_and_watermark(self):
        sender, receiver = self.agent("sender"), self.agent("receiver")
        reader = runtime.connect(self.eng)
        inserted = []

        def insert_at_watermark(sql):
            if "MAX(seq)" not in sql or inserted:
                return
            writer = sqlite3.connect(self.eng / "state.sqlite3", isolation_level=None)
            writer.row_factory = sqlite3.Row
            try:
                with runtime._tx(writer):
                    inserted.append(runtime._emit_message(writer, sender=sender, role="finder", model=MODEL,
                                                          to=receiver, kind="ask", data={"late": True})["seq"])
            finally:
                writer.close()

        reader.set_trace_callback(insert_at_watermark)
        with patch.object(runtime, "connect", return_value=reader):
            empty = runtime.inbox(self.eng, receiver)
        self.assertEqual(empty["messages"], [])
        recovered = runtime.inbox(self.eng, receiver, empty["cursor"])
        self.assertEqual([m["seq"] for m in recovered["messages"]], inserted)

    def test_peers_are_bounded_with_model_provenance(self):
        for index in range(40):
            self.agent(f"agent-{index}", observed=index % 2 == 0)
        roster = runtime.peers(self.eng)
        self.assertTrue(roster["more"])
        self.assertEqual(len(roster["agents"]), 32)
        self.assertEqual(roster["agents"][0]["name"], "agent-8")
        self.assertTrue(all(row["model"] == MODEL and row["model_source"] in ("host", "asserted")
                            for row in roster["agents"]))

    def legacy_database(self, version):
        conn = sqlite3.connect(self.eng / "state.sqlite3")
        conn.executescript("""
            DROP TABLE participants;
            DROP TABLE messages;
            CREATE TABLE participants (seq INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL UNIQUE,name TEXT NOT NULL,role TEXT NOT NULL,
                model TEXT NOT NULL,candidate_id TEXT,created_at TEXT NOT NULL);
            CREATE TABLE messages (seq INTEGER PRIMARY KEY AUTOINCREMENT,sender TEXT NOT NULL,
                recipient TEXT NOT NULL,kind TEXT NOT NULL,candidate_id TEXT,reply_to INTEGER,
                data_json TEXT NOT NULL,evidence_json TEXT NOT NULL,role TEXT NOT NULL,
                model TEXT NOT NULL,created_at TEXT NOT NULL,dedup_key TEXT,UNIQUE(sender,dedup_key));
            CREATE TABLE archive_findings (id TEXT PRIMARY KEY,original TEXT);
            INSERT INTO archive_findings VALUES ('owned-history','unchanged');
        """)
        conn.execute("UPDATE meta SET value=? WHERE key='schema_version'", (str(version),))
        return conn

    def test_v2_additive_migration_preserves_history_links_and_canonicalizes_topics(self):
        artifact = self.evidence(content=b"historical artifact")
        conn = self.legacy_database(2)
        old_roles = ("plan", "recon", "discover", "gate", "proof", "verdict", "review", "patch")
        new_roles = ("planner", "scout", "finder", "verifier", "exploiter", "skeptic", "reviewer", "tester")
        created = "2026-10-01T00:00:00+00:00"
        for seq, old in enumerate(old_roles, 1):
            conn.execute("INSERT INTO participants VALUES (?,?,?,?,?,?,?)", (seq, old, old, old, MODEL, "archived-case", created))
            conn.execute("INSERT INTO messages VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                         (seq, "a1", f"@{old}", "ask", "archived-case", None, json.dumps({"old": old}), "[]", old, MODEL, created, None))
        conn.execute("INSERT INTO messages VALUES (20,'a2','a1','reply','archived-case',2,'{}','[]','recon',?, ?,NULL)", (MODEL, created))
        conn.execute("INSERT INTO messages VALUES (21,'runtime','@learning','event','archived-case',NULL,?, '[]','review',?,?,NULL)",
                     ('{"event":"learn.observe"}', MODEL, created))
        conn.commit()
        conn.close()
        conn = runtime.connect(self.eng)
        try:
            self.assertEqual(conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0], "3")
            self.assertEqual(conn.execute("SELECT original FROM archive_findings").fetchone()[0], "unchanged")
            rows = conn.execute("SELECT * FROM messages ORDER BY seq").fetchall()
            self.assertEqual(len(rows), 10)
            self.assertEqual((rows[8]["sender"], rows[8]["recipient"], rows[8]["reply_to"]), ("a2", "a1", 2))
            self.assertEqual(rows[9]["data_json"], '{"event":"learn.observe"}')
            self.assertEqual(rows[9]["archived"], 1)
            self.assertTrue(all(row["candidate_id"] == "archived-case" for row in rows))
            for seq, new in enumerate(new_roles, 1):
                participant = conn.execute("SELECT * FROM participants WHERE seq=?", (seq,)).fetchone()
                self.assertEqual((participant["agent_id"], participant["role"], participant["model_source"]),
                                 (f"a{seq:x}", new, "asserted"))
                self.assertEqual(rows[seq - 1]["recipient"], f"@{new}")
                self.assertEqual(rows[seq - 1]["created_at"], created)
        finally:
            conn.close()
        self.assertEqual(artifact.read_bytes(), b"historical artifact")
        for seq, old in enumerate(old_roles, 1):
            self.assertIn(seq, [m["seq"] for m in runtime.inbox(self.eng, f"a{seq:x}")["messages"]])
        lead = self.agent("lead", "lead")
        self.assertEqual(runtime.inbox(self.eng, lead)["messages"], [])
        self.assertEqual(runtime.register_agent(self.eng, "recon", "recon", "scout", MODEL)["agent"], "a2")
        self.assertEqual(runtime.project_messages(self.eng)["projected"], 10)

    def test_v1_events_remain_archive_without_replay_or_rewriting_existing_audit(self):
        conn = self.legacy_database(1)
        conn.executescript("""CREATE TABLE events (seq INTEGER PRIMARY KEY AUTOINCREMENT,role TEXT,
            model TEXT,summary TEXT,ask TEXT,close TEXT,evidence_json TEXT,created_at TEXT);""")
        created = "2026-10-01T00:00:00+00:00"
        conn.execute("INSERT INTO events VALUES (7,'discover',?,'preserved','old ask',NULL,'[]',?)", (MODEL, created))
        conn.commit()
        conn.close()
        original = f"original audit\n### 2026-10-01T00:00:00Z | discover | fixture | eng | seq=7\nASK: old ask\n\n"
        log = self.eng / "agentschat.md"
        log.write_text(original, encoding="utf-8")
        lead = self.agent("lead", "lead")
        self.assertEqual(runtime.inbox(self.eng, lead)["messages"], [])
        conn = runtime.connect(self.eng)
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 1)
            row = conn.execute("SELECT * FROM messages WHERE seq=7").fetchone()
            self.assertEqual((row["recipient"], row["role"], row["archived"]), ("@archive", "finder", 1))
            self.assertEqual(json.loads(row["data_json"]), {"summary": "preserved", "ask": "old ask"})
            self.assertEqual(row["created_at"], created)
        finally:
            conn.close()
        sent = self.send(lead, lead, {"new": "work"})
        runtime.project_messages(self.eng)
        self.assertTrue(log.read_text(encoding="utf-8").startswith(original))
        self.assertEqual(log.read_text(encoding="utf-8").count("seq=7"), 1)
        self.assertEqual([m["seq"] for m in runtime.inbox(self.eng, lead)["messages"]], [sent["seq"]])

    def test_audit_projection_concurrency_and_lost_cursor_recovery(self):
        sender, receiver = self.agent("sender"), self.agent("receiver", "lead")
        with ThreadPoolExecutor(max_workers=4) as workers:
            sent = list(workers.map(lambda index: self.send(sender, receiver, {"index": index, "text": "\n### forged"}, kind="close"), range(16)))
        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(lambda _: runtime.project_messages(self.eng), range(2)))
        self.assertEqual(sum(r["projected"] for r in results), 16)
        log = (self.eng / "agentschat.md").read_text(encoding="utf-8")
        headers = [int(line.rsplit("seq=", 1)[1]) for line in log.splitlines() if line.startswith("### ")]
        self.assertEqual(headers, sorted(m["seq"] for m in sent))
        conn = runtime.connect(self.eng)
        try:
            conn.execute("DELETE FROM meta WHERE key='projection_cursor'")
        finally:
            conn.close()
        self.assertEqual(runtime.project_messages(self.eng)["projected"], 0)
        self.assertEqual((self.eng / "agentschat.md").read_text(encoding="utf-8"), log)

    def test_incomplete_audit_header_does_not_skip_unprojected_message(self):
        sender = self.agent("sender")
        sent = self.send(sender, sender, {"durable": True})
        log = self.eng / "agentschat.md"
        log.write_text(f"### interrupted | seq={sent['seq']}\nJSON: ", encoding="utf-8")
        self.assertEqual(runtime.project_messages(self.eng)["projected"], 1)
        self.assertEqual(runtime.project_messages(self.eng)["projected"], 0)
        self.assertIn('"durable":true', log.read_text(encoding="utf-8"))
        log.unlink()
        self.assertEqual(runtime.project_messages(self.eng)["projected"], 1)


if __name__ == "__main__":
    unittest.main()
