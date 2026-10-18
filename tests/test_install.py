from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from praise import config, installation
from praise.errors import PraiseError


@contextmanager
def packaged_resources():
    """Small installation payload for failure and rollback controls."""
    defaults = config.role_bytes(config.default_roles())
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        files = {"roles.json": defaults, "integration/RULES.md": b"Rules\n",
                 "integration/extensions/praise-router.js": b"router\n",
                 "integration/extensions/json-client.mjs": b"client\n",
                 "integration/skills/praise-coordination/SKILL.md": b"coordination\n"}
        files.update({f"integration/agents/{role}.md": role.encode() for role in config.ROLE_NAMES})
        for name, data in files.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        with patch("importlib.resources.files", return_value=root):
            yield


class InstallTests(unittest.TestCase):
    def test_owned_yaml_cleanup_is_precisely_scoped_and_idempotent(self):
        source = 'theme:\n  finder: custom\ntask:\n  concurrency: 2\n  agentModelOverrides:\n    custom-worker: vendor/custom\n    pentest-finder: vendor/old\n    finder: vendor/also-old\n  worktrees: false\nworkspace:\n  finder: existing\n'
        result = installation.model_settings(source).decode()
        expected = source.replace('    pentest-finder: vendor/old\n', '').replace('    finder: vendor/also-old\n', '')
        self.assertEqual(result, expected)
        self.assertEqual(installation.model_settings(result).decode(), result)
        emptied = installation.model_settings('task:\n  agentModelOverrides:\n    finder: vendor/old\n').decode()
        self.assertEqual(emptied, 'task:\n  agentModelOverrides: {}\n')
        self.assertEqual(installation.model_settings(emptied).decode(), emptied)
        self.assertEqual(installation.model_settings('theme: &theme {finder: custom}\n'), b'theme: &theme {finder: custom}\n')
        crlf = 'theme: custom\r\ntask:\r\n  agentModelOverrides:\r\n    finder: vendor/old\r\n    custom: vendor/kept\r\n'
        self.assertEqual(installation.model_settings(crlf), crlf.replace('    finder: vendor/old\r\n', '').encode())

    def test_unsafe_yaml_forms_are_refused(self):
        cases = ('task: {agentModelOverrides: {finder: model}}\n', 'task:\n  agentModelOverrides: {custom: model}\n', 'task:\ntask:\n', 'task: *alias\n', 'task:\n  <<: *other\n', 'task:\n  agentModelOverrides:\n    finder: &model vendor/a\n', 'task:\n  agentModelOverrides:\n    finder: vendor/a\n    finder: vendor/b\n', 'task:\n  agentModelOverrides:\n    finder: |\n      vendor/a\n', '"task":\n  agentModelOverrides:\n    finder: vendor/a\n')
        for source in cases:
            with self.subTest(source=source), self.assertRaises(PraiseError):
                installation.model_settings(source)


    def test_reinstall_preserves_choices_and_unrelated_settings(self):
        with tempfile.TemporaryDirectory() as temp, packaged_resources():
            home = Path(temp)
            installation.install(home)
            config.set_role_model('investigator', 'custom/new-model:xhigh', home)
            directory = config.agent_dir(home)
            roles = (directory / 'praise.json').read_bytes()
            yaml = directory / 'config.yml'
            yaml.write_text('theme: custom\ntask:\n  concurrency: 3\n  agentModelOverrides:\n    unrelated: vendor/custom\n')
            original = yaml.read_bytes()
            result = installation.install(home)
            self.assertEqual(result['installed'], 0)
            self.assertEqual((directory / 'praise.json').read_bytes(), roles)
            self.assertEqual(yaml.read_bytes(), original)
            self.assertEqual(config.dispatch('investigator', home)['model'], 'custom/new-model:xhigh')

    def test_schema3_cutover_uses_fixed_defaults_and_rollback_restores_old_files(self):
        with tempfile.TemporaryDirectory() as temp, packaged_resources():
            home = Path(temp)
            directory = config.agent_dir(home)
            old_catalog = {
                "schema_version": 3,
                "models": {
                    role: f"legacy/{role}:high"
                    for role in (*config.REMOVED_ROLE_NAMES, "scout")
                },
            }
            directory.mkdir(parents=True)
            role_path = directory / "praise.json"
            role_path.write_text(json.dumps(old_catalog))
            old_role = directory / "agents/finder.md"
            old_role.parent.mkdir()
            old_role.write_text("old finder")
            result = installation.install(home, overwrite=True)
            self.assertEqual(config.load_roles(home), config.default_roles())
            self.assertFalse(old_role.exists())
            self.assertTrue((directory / "agents/investigator.md").exists())
            records = json.loads((Path(result["backup"]) / "manifest.json").read_text())
            self.assertTrue(any(row["path"] == "praise.json" for row in records))
            self.assertTrue(any(row["path"] == "agents/finder.md" for row in records))
            installation.rollback(home, Path(result["backup"]))
            self.assertEqual(json.loads(role_path.read_text()), old_catalog)
            self.assertEqual(old_role.read_text(), "old finder")
            self.assertFalse((directory / "agents/investigator.md").exists())

    def test_first_install_preserves_existing_role_model_overrides(self):
        with tempfile.TemporaryDirectory() as temp, packaged_resources():
            home = Path(temp)
            directory = home / ".omp/agent"
            directory.mkdir(parents=True)
            (directory / "config.yml").write_text(
                "theme:\n  finder: blue\ntask:\n  agentModelOverrides:\n"
                "    investigator: custom/selected-model:high\n"
                "    security-reviewer: custom/removed-model\n"
                "    custom-worker: vendor/unrelated\n"
            )
            installation.install(home, overwrite=True)
            self.assertEqual(
                config.dispatch("investigator", home)["model"],
                "custom/selected-model:high",
            )
            self.assertEqual(
                config.dispatch("analyst", home)["model"],
                "opencode-go/deepseek-v4.1-flash:high",
            )
            self.assertEqual(
                (directory / "config.yml").read_text(),
                "theme:\n  finder: blue\ntask:\n  agentModelOverrides:\n"
                "    custom-worker: vendor/unrelated\n",
            )

    def test_conflicts_are_backed_up_and_tombstones_are_reversible(self):
        with tempfile.TemporaryDirectory() as temp, packaged_resources():
            home = Path(temp)
            directory = config.agent_dir(home)
            directory.mkdir(parents=True)
            legacy = directory / 'crew.json'
            legacy.write_text(json.dumps(
                {'roles': {'investigator': {'models': ['vendor/investigator:high']}}}
            ))
            original = legacy.read_bytes()
            obsolete = directory / 'extensions/crew-router.js'
            obsolete.parent.mkdir()
            obsolete.write_bytes(b'old-router')
            unrelated = directory / 'agents/custom-worker.md'
            unrelated.parent.mkdir()
            unrelated.write_bytes(b'user-owned')
            with self.assertRaises(PraiseError):
                installation.install(home)
            self.assertEqual(legacy.read_bytes(), original)
            self.assertFalse((directory / 'praise.json').exists())
            result = installation.install(home, overwrite=True)
            self.assertFalse(legacy.exists())
            self.assertFalse(obsolete.exists())
            self.assertEqual(config.dispatch('investigator', home)['model'], 'vendor/investigator:high')
            records = json.loads((Path(result['backup']) / 'manifest.json').read_text())
            self.assertTrue(any(record['path'] == 'crew.json' and record['installed_sha256'] is None for record in records))
            installation.rollback(home, Path(result['backup']))
            self.assertEqual(legacy.read_bytes(), original)
            self.assertEqual(obsolete.read_bytes(), b'old-router')
            self.assertEqual(unrelated.read_bytes(), b'user-owned')
            self.assertFalse((directory / 'praise.json').exists())

    def test_recreated_tombstone_blocks_entire_rollback(self):
        with tempfile.TemporaryDirectory() as temp, packaged_resources():
            home = Path(temp)
            directory = config.agent_dir(home)
            directory.mkdir(parents=True)
            (directory / 'crew.json').write_text('{}')
            result = installation.install(home, overwrite=True)
            (directory / 'crew.json').write_bytes(b'new-user-work')
            with self.assertRaises(PraiseError):
                installation.rollback(home, Path(result['backup']))
            self.assertEqual((directory / 'crew.json').read_bytes(), b'new-user-work')
            self.assertTrue((directory / 'extensions/praise-router.js').exists())

    def test_failed_install_rolls_back_writes_and_removals(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            directory = config.agent_dir(home)
            directory.mkdir(parents=True)
            old = directory / 'crew.json'
            old.write_bytes(b'old-catalog')
            new = directory / 'new-owned'
            entries = [(old, None, 0), (new, b'new-content', 0o600)]
            real_write = installation.atomic_write
            def fail_new(target, data, mode):
                if target == new:
                    raise OSError('injected installation failure')
                return real_write(target, data, mode)
            with patch('praise.installation.atomic_write', side_effect=fail_new), self.assertRaises(OSError):
                installation._apply(home, directory, entries, overwrite=True, dry_run=False)
            self.assertEqual(old.read_bytes(), b'old-catalog')
            self.assertFalse(new.exists())

    def test_unsafe_yaml_refused_before_any_owned_file_changes(self):
        with tempfile.TemporaryDirectory() as temp, packaged_resources():
            home = Path(temp)
            directory = config.agent_dir(home)
            directory.mkdir(parents=True)
            yaml = directory / 'config.yml'
            yaml.write_text('task: &defaults {agentModelOverrides: {finder: vendor/old}}\n')
            original = yaml.read_bytes()
            with self.assertRaises(PraiseError):
                installation.install(home, overwrite=True)
            self.assertEqual(yaml.read_bytes(), original)
            self.assertEqual({entry.name for entry in directory.iterdir()}, {'config.yml'})

    def test_profile_uses_same_agent_root_as_dispatch(self):
        with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryDirectory() as profile, packaged_resources():
            home = Path(temp)
            with patch.dict(os.environ, {'PI_CODING_AGENT_DIR': profile}), patch('praise.installation.Path.home', return_value=home):
                installation.install()
                config.set_role_model('investigator', 'vendor/profile:high')
                self.assertTrue((Path(profile) / 'extensions/praise-router.js').is_file())
                self.assertEqual(config.dispatch('investigator')['model'], 'vendor/profile:high')
                self.assertFalse((home / '.omp/agent/praise.json').exists())

    def test_rollback_refuses_another_profile_before_restoring_any_files(self):
        with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryDirectory() as profile, packaged_resources():
            home = Path(temp)
            result = installation.install(home)
            original = (config.agent_dir(home) / 'praise.json').read_bytes()
            with self.assertRaises(PraiseError):
                installation.rollback(home, Path(result['backup']), directory=Path(profile))
            self.assertEqual((config.agent_dir(home) / 'praise.json').read_bytes(), original)
            self.assertTrue((home / '.local/bin/praise').exists())

    def test_symlink_and_parent_escape_are_refused(self):
        with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryDirectory() as outside:
            home = Path(temp)
            (home / 'linked').symlink_to(outside, target_is_directory=True)
            with self.assertRaises(PraiseError):
                installation.safe(home, 'linked/owned')
            with self.assertRaises(PraiseError):
                installation.safe(home, '../outside')


if __name__ == '__main__':
    unittest.main()
