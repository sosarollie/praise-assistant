"""Public configuration, main launch and resident protocol behavior."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from praise import cli, config, runtime


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.profile = self.root / "profile"
        self.source = self.root / "source"
        self.source.mkdir()
        self.eng = self.root / "engagement"
        self.environment = patch.dict(os.environ, {"PI_CODING_AGENT_DIR": str(self.profile)})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def call(self, argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
            code = cli.main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def initialize(self):
        runtime.init_engagement(self.eng, program="owned fixture", basis="offline validation",
                                assets=[str(self.source)])

    def launcher(self):
        extension = self.profile / "extensions/praise-router.js"
        extension.parent.mkdir(parents=True, exist_ok=True)
        extension.write_text("// launch boundary fixture\n")
        return extension

    def resident(self, commands):
        frames = "".join(json.dumps({"id": i, "args": args}) + "\n" for i, args in enumerate(commands))
        stdin = type("Input", (), {"buffer": io.BytesIO(frames.encode())})()
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("sys.stdin", stdin), patch("sys.stdout", stdout), patch("sys.stderr", stderr):
            code = cli.main(["--engagement", str(self.eng), "serve"])
        self.assertEqual(code, 0, stderr.getvalue())
        return [json.loads(line) for line in stdout.getvalue().splitlines()]

    def test_model_change_is_visible_without_an_engagement(self):
        code, out, err = self.call(["setAgent", "--role", "analyst", "--model", "vendor/new-model:high"])
        self.assertEqual((code, err), (0, ""))
        code, out, err = self.call(["getAgents"])
        self.assertEqual((code, err), (0, ""))
        self.assertIn("new-model", out)
        self.assertIn("1 changed from the packaged defaults", out)
        self.assertEqual(out.count("(packaged default:"), 1)
        self.assertNotIn("Participants", out)
        code, out, err = self.call(["getAgents", "--json"])
        self.assertEqual((code, err), (0, ""))
        displayed = json.loads(out)
        self.assertEqual(displayed["schema_version"], 4)
        roles = {row["role"]: row for row in displayed["roles"]}
        self.assertEqual(set(roles), set(config.ROLE_NAMES))
        self.assertEqual(roles["analyst"]["model"], "vendor/new-model:high")
        self.assertEqual(config.dispatch("analyst")["model"], "vendor/new-model:high")
        self.assertNotIn("participants", displayed)

    def test_get_agents_distinguishes_asserted_from_host_identity(self):
        self.initialize()
        asserted = runtime.register_agent(self.eng, "manual", "manual", "investigator", "vendor/assertion")
        observed = runtime.register_agent(self.eng, "host", "host", "investigator", "vendor/actual", observed=True)
        code, out, err = self.call(["getAgents", "--engagement", str(self.eng), "--json"])
        self.assertEqual((code, err), (0, ""))
        participants = {row["id"]: row for row in json.loads(out)["participants"]["agents"]}
        self.assertEqual(participants[asserted["agent"]]["model_source"], "asserted")
        self.assertEqual(participants[observed["agent"]]["model_source"], "host")
        self.assertEqual(participants[observed["agent"]]["model"], "vendor/actual")
        human = self.call(["getAgents", "--engagement", str(self.eng)])
        self.assertEqual(human[0], 0)
        self.assertIn("Participants (2 registered in", human[1])
        self.assertIn("vendor/assertion", human[1])
        self.assertIn("vendor/actual", human[1])

    def test_removed_commands_and_invalid_model_choices_fail_without_writes(self):
        cases = (["init"], ["lead"], ["setrole"], ["candidate"],
                 ["setAgent", "--role", "finder", "--model", "vendor/model"],
                 ["setAgent", "--role", "investigator", "--model", "invalid"])
        for argv in cases:
            with self.subTest(argv=argv):
                code, out, err = self.call(argv)
                self.assertNotEqual(code, 0)
                self.assertEqual(out, "")
                self.assertIn("error", json.loads(err))
        self.assertFalse(self.profile.exists())

    def test_dispatch_requires_scope_and_selects_the_persistent_model(self):
        config.set_role_model("scout", "vendor/current:high")
        code, out, err = self.call(["--engagement", str(self.eng), "dispatch", "--role", "scout"])
        self.assertNotEqual(code, 0)
        self.assertFalse(self.eng.exists())
        self.initialize()
        code, out, err = self.call(["--engagement", str(self.eng), "dispatch", "--role", "scout"])
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(json.loads(out), {"role": "scout", "agent": "scout", "model": "vendor/current:high"})

    def test_new_main_initializes_and_launches_without_a_lead_selector(self):
        extension = self.launcher()
        with patch("praise.cli.os.execvp", side_effect=OSError("stopped at process boundary")) as execute:
            code, out, err = self.call([
                "startLeadAgent", "--directory", str(self.eng), "--program", "owned fixture",
                "--basis", "offline validation", "--asset", str(self.source), "--",
                "--no-extensions", "--no-session", "-p", "hello",
            ])
        self.assertEqual(code, 1)
        self.assertIn("native main launcher failed", json.loads(err)["error"])
        self.assertEqual(runtime.load_scope(self.eng)["source_roots"], [str(self.source)])
        self.assertEqual(execute.call_args.args, ("omp", [
            "omp", "--cwd", str(self.eng), "-e", str(extension),
            "--no-extensions", "--no-session", "-p", "hello",
        ]))

    def test_resume_preserves_scope_and_uses_the_terminal_model(self):
        extension = self.launcher()
        self.initialize()
        scope = (self.eng / "scope.json").read_bytes()
        with patch("praise.cli.os.execvp", side_effect=OSError("unavailable host execution")) as execute:
            code, out, err = self.call(["startLeadAgent", "--directory", str(self.eng), "--", "--print", "hello"])
        self.assertEqual(code, 1)
        self.assertEqual((self.eng / "scope.json").read_bytes(), scope)
        self.assertEqual(execute.call_args.args[1], [
            "omp", "--cwd", str(self.eng), "-e", str(extension), "--print", "hello",
        ])
        self.assertEqual(execute.call_count, 1)

    def test_native_arguments_are_passed_through_without_override_guards(self):
        self.launcher()
        self.initialize()
        for arguments in (["--model", "vendor/other"], ["-mother"], ["--thinking=low"], ["--profile", "other"]):
            with self.subTest(arguments=arguments):
                with patch("praise.cli.os.execvp", side_effect=OSError("stopped at process boundary")) as execute:
                    code, out, err = self.call(["startLeadAgent", "--directory", str(self.eng), "--", *arguments])
                self.assertEqual(code, 1)
                self.assertIn("native main launcher failed", json.loads(err)["error"])
                self.assertEqual(execute.call_args.args[1][-len(arguments):], arguments)

    def test_missing_scope_or_integration_does_not_create_an_engagement(self):
        code, out, err = self.call(["startLeadAgent", "--directory", str(self.eng)])
        self.assertIn("run praise install", json.loads(err)["error"])
        self.launcher()
        code, out, err = self.call(["startLeadAgent", "--directory", str(self.eng)])
        self.assertIn("new engagements require", json.loads(err)["error"])
        self.assertFalse(self.eng.exists())

    def test_resident_cannot_configure_launch_or_escape_its_engagement(self):
        self.initialize()
        initial = config.load_roles()
        commands = [["install"], ["setAgent", "--role", "lead", "--model", "vendor/model"],
                    ["getAgents"], ["startLeadAgent", "--directory", "/other"], ["serve"],
                    ["scope", "--engagement", "/other"], ["scope", "--help"], ["scope"]]
        replies = self.resident(commands)
        self.assertTrue(all(not row["ok"] for row in replies[:-1]))
        self.assertEqual(replies[-1]["data"]["program"], "owned fixture")
        self.assertEqual(config.load_roles(), initial)

    def test_resident_registration_commits_parent_notification_and_provenance(self):
        self.initialize()
        parent = runtime.register_agent(self.eng, "main", "main", "main", "vendor/main", observed=True)["agent"]
        replies = self.resident([["register", "--session", "child", "--name", "worker", "--role", "investigator",
                                  "--model", "vendor/model", "--parent", parent, "--observed"]])
        self.assertTrue(replies[0]["ok"])
        child = replies[0]["data"]["agent"]
        message = runtime.inbox(self.eng, parent)["messages"][0]
        self.assertEqual(message["from"], child)
        self.assertEqual(message["data"]["event"], "agent.started")
        self.assertEqual(message["data"]["model_source"], "host")

    def test_uncertain_committed_resident_write_is_not_replayed(self):
        self.initialize()
        sender = runtime.register_agent(self.eng, "sender", "sender", "investigator", "vendor/model")["agent"]
        send = runtime.send_message

        def commit_then_fail(*args, **kwargs):
            send(*args, **kwargs)
            raise OSError("response unavailable after commit")

        with patch("praise.cli.runtime.send_message", side_effect=commit_then_fail):
            replies = self.resident([["message", "--sender", sender, "--model", "vendor/model", "--to", sender,
                                      "--kind", "ask", "--data", '{"need":"help"}']])
        self.assertFalse(replies[0]["ok"])
        messages = runtime.inbox(self.eng, sender)["messages"]
        self.assertEqual([row["data"] for row in messages], [{"need": "help"}])


if __name__ == "__main__":
    unittest.main()
