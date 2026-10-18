from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from praise import config
from praise.errors import PraiseError


class ConfigTests(unittest.TestCase):
    def test_default_roles_and_unknown_family_are_supported(self):
        with tempfile.TemporaryDirectory() as temp:
            self.assertEqual(tuple(config.load_roles(temp)["models"]), config.ROLE_NAMES)
            self.assertEqual(
                config.dispatch("investigator", temp)["model"],
                "openai-codex/gpt-5.6-sol:xhigh",
            )
            config.set_role_model("analyst", "private-vendor/new-model:custom-effort", temp)
            self.assertEqual(
                config.dispatch("analyst", temp),
                {"role": "analyst", "agent": "analyst",
                 "model": "private-vendor/new-model:custom-effort"},
            )

    def test_set_agent_changes_only_praise_json_and_preserves_other_roles(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = config.agent_dir(temp)
            directory.mkdir(parents=True)
            yaml = directory / "config.yml"
            yaml.write_text("task: {unrelated: untouched}\ntheme: custom\n")
            crew = directory / "crew.json"
            crew.write_text(json.dumps(
                {"roles": {"investigator": {"models": ["vendor/investigator:high"]}}}
            ))
            original_yaml, original_crew = yaml.read_bytes(), crew.read_bytes()
            initial = config.load_roles(temp)
            config.set_role_model("analyst", "vendor/analyst:high", temp)
            configured = config.load_roles(temp)
            self.assertEqual(configured["models"]["investigator"], "vendor/investigator:high")
            self.assertEqual(configured["models"]["scout"], initial["models"]["scout"])
            self.assertEqual(configured["models"]["analyst"], "vendor/analyst:high")
            self.assertEqual(yaml.read_bytes(), original_yaml)
            self.assertEqual(crew.read_bytes(), original_crew)
            crew.write_text("invalid legacy JSON after migration")
            self.assertEqual(config.load_roles(temp), configured)

    def test_invalid_roles_and_selectors_leave_configuration_untouched(self):
        with tempfile.TemporaryDirectory() as temp:
            config.load_roles(temp)
            path = config.agent_dir(temp) / "praise.json"
            original = path.read_bytes()
            with self.assertRaises(PraiseError):
                config.set_role_model("finder", "vendor/model", temp)
            for selector in ("", "model", "vendor/", "vendor//model", "vendor/model/",
                             "vendor/model:high:extra", "vendor/model\n", " vendor/model",
                             "vendor/model;command", "vendor/model high"):
                with self.subTest(selector=selector), self.assertRaises(PraiseError):
                    config.set_role_model("analyst", selector, temp)
            self.assertEqual(path.read_bytes(), original)

    def test_profiles_and_explicit_home_share_one_resolution_contract(self):
        with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryDirectory() as profile:
            with patch.dict(os.environ, {"PI_CODING_AGENT_DIR": profile}):
                self.assertEqual(config.agent_dir(), Path(profile))
                self.assertEqual(config.agent_dir(temp), Path(temp) / ".omp/agent")
                config.set_role_model("investigator", "vendor/profile:xhigh")
                self.assertEqual(config.dispatch("investigator")["model"], "vendor/profile:xhigh")
                self.assertFalse((Path(temp) / ".omp/agent/praise.json").exists())

    def test_corrupt_installed_config_does_not_fall_back(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = config.agent_dir(temp)
            directory.mkdir(parents=True)
            path = directory / "praise.json"
            path.write_text('{"schema_version": 4, "models": {"lead": "vendor/model"}}')
            with self.assertRaises(PraiseError):
                config.dispatch("investigator", temp)
            self.assertIn('"lead"', path.read_text())

    def test_schema3_requires_install_without_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = config.agent_dir(temp)
            directory.mkdir(parents=True)
            path = directory / "praise.json"
            legacy = {
                "schema_version": 3,
                "models": {
                    role: f"vendor/{role}:high"
                    for role in (*config.REMOVED_ROLE_NAMES, "scout")
                },
            }
            path.write_text(json.dumps(legacy))
            original = path.read_bytes()
            with self.assertRaisesRegex(PraiseError, "requires `praise install`"):
                config.load_roles(temp)
            self.assertEqual(path.read_bytes(), original)

    def test_atomic_replace_failure_preserves_current_selector(self):
        with tempfile.TemporaryDirectory() as temp:
            config.load_roles(temp)
            path = config.agent_dir(temp) / "praise.json"
            original = path.read_bytes()
            with patch("praise.config.os.replace", side_effect=OSError("injected replace failure")):
                with self.assertRaises(OSError):
                    config.set_role_model("investigator", "vendor/changed:xhigh", temp)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual({entry.name for entry in path.parent.iterdir()},
                             {"praise.json", ".praise.lock"})

    def test_migrates_matching_legacy_role_once(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = config.agent_dir(temp)
            directory.mkdir(parents=True)
            (directory / "crew.json").write_text(json.dumps({
                "roles": {"investigator": {"models": ["vendor/first:high", "vendor/second:high"]}}
            }))
            self.assertEqual(config.load_roles(temp)["models"]["investigator"], "vendor/first:high")
            self.assertEqual(set(config.load_roles(temp)["models"]), set(config.ROLE_NAMES))


if __name__ == "__main__":
    unittest.main()
