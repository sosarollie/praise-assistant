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
            self.assertEqual(config.dispatch("lead", temp)["model"], "opencode-go/step-5-preview-free:xhigh")
            config.set_role_model("finder", "private-vendor/new-model:custom-effort", temp)
            self.assertEqual(config.dispatch("finder", temp), {"role": "finder", "agent": "finder", "model": "private-vendor/new-model:custom-effort"})

    def test_set_agent_changes_only_praise_json_and_preserves_other_roles(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = config.agent_dir(temp)
            directory.mkdir(parents=True)
            yaml = directory / "config.yml"
            yaml.write_text("task: {unrelated: untouched}\ntheme: custom\n")
            crew = directory / "crew.json"
            crew.write_text(json.dumps({"lead_model": "vendor/lead:xhigh", "roles": {"finder": {"models": ["vendor/finder:high"]}}}))
            original_yaml, original_crew = yaml.read_bytes(), crew.read_bytes()
            initial = config.load_roles(temp)
            config.set_role_model("skeptic", "vendor/skeptic:high", temp)
            configured = config.load_roles(temp)
            self.assertEqual(configured["models"]["lead"], "vendor/lead:xhigh")
            self.assertEqual(configured["models"]["finder"], "vendor/finder:high")
            self.assertEqual(configured["models"]["scout"], initial["models"]["scout"])
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
                config.set_role_model("finder-deep", "vendor/model", temp)
            for selector in ("", "model", "vendor/", "vendor//model", "vendor/model/", "vendor/model:high:extra", "vendor/model\n", " vendor/model", "vendor/model;command", "vendor/model high"):
                with self.subTest(selector=selector), self.assertRaises(PraiseError):
                    config.set_role_model("finder", selector, temp)
            self.assertEqual(path.read_bytes(), original)

    def test_profiles_and_explicit_home_share_one_resolution_contract(self):
        with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryDirectory() as profile:
            with patch.dict(os.environ, {"PI_CODING_AGENT_DIR": profile}):
                self.assertEqual(config.agent_dir(), Path(profile))
                self.assertEqual(config.agent_dir(temp), Path(temp) / ".omp/agent")
                config.set_role_model("lead", "vendor/profile:xhigh")
                self.assertEqual(config.dispatch("lead")["model"], "vendor/profile:xhigh")
                self.assertFalse((Path(temp) / ".omp/agent/praise.json").exists())

    def test_corrupt_installed_config_does_not_fall_back(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = config.agent_dir(temp)
            directory.mkdir(parents=True)
            path = directory / "praise.json"
            path.write_text('{"schema_version": 3, "models": {"lead": "vendor/model"}}')
            with self.assertRaises(PraiseError):
                config.dispatch("lead", temp)
            self.assertIn('"lead"', path.read_text())

    def test_atomic_replace_failure_preserves_current_selector(self):
        with tempfile.TemporaryDirectory() as temp:
            config.load_roles(temp)
            path = config.agent_dir(temp) / "praise.json"
            original = path.read_bytes()
            with patch("praise.config.os.replace", side_effect=OSError("injected replace failure")):
                with self.assertRaises(OSError):
                    config.set_role_model("lead", "vendor/changed:xhigh", temp)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual({entry.name for entry in path.parent.iterdir()}, {"praise.json", ".praise.lock"})

    def test_migrates_prefixed_legacy_roles_once(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = config.agent_dir(temp)
            directory.mkdir(parents=True)
            (directory / "crew.json").write_text(json.dumps({"lead_model": "vendor/lead:high", "roles": {"pentest-finder": {"models": ["vendor/first:high", "vendor/second:high"]}, "pentest-finder-deep": {"models": ["vendor/deep"]}}}))
            self.assertEqual(config.load_roles(temp)["models"]["finder"], "vendor/first:high")
            self.assertNotIn("finder-deep", config.load_roles(temp)["models"])


if __name__ == "__main__":
    unittest.main()
