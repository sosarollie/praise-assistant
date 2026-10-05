from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from scripts.install import atomic_write, digest, model_settings, rollback, safe


class InstallTests(unittest.TestCase):
    def test_owned_model_updates_preserve_other_settings(self):
        source = 'theme:\n  dark: custom\ntask:\n  concurrency: 2\n  agentModelOverrides:\n    custom-worker: vendor/custom\n    pentest-finder: vendor/old\n  worktrees: false\nworkspace:\n  label: existing\n'
        result = model_settings(source, {'roles': {'pentest-finder': {'models': ['vendor/new']}}}).decode()
        self.assertIn('    custom-worker: vendor/custom\n', result)
        self.assertIn('    pentest-finder: vendor/new\n', result)
        self.assertNotIn('vendor/old', result)
        self.assertIn('  worktrees: false\nworkspace:\n  label: existing\n', result)
        self.assertIn('  concurrency: 2\n', result)
        self.assertIn('theme:\n  dark: custom\n', result)
        self.assertEqual(model_settings(result, {'roles': {'pentest-finder': {'models': ['vendor/new']}}}).decode(), result)

    def test_complex_settings_fail_without_silently_overwriting(self):
        for source in ('task: {agentModelOverrides: {custom: model}}\n', 'task:\n  agentModelOverrides: {custom: model}\n', 'task:\ntask:\n'):
            with self.subTest(source=source), self.assertRaises(ValueError):
                model_settings(source, {'roles': {'worker': {'models': ['vendor/model']}}})

    def test_rollback_restores_old_bytes_and_removes_owned_new_files(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp).resolve()
            backup = home / '.local/state/praiseassistant/install-backups/test'
            backup.mkdir(parents=True)
            original, installed = b'original\n', b'installed\n'
            atomic_write(home / 'existing', installed, 0o600)
            atomic_write(home / 'new', installed, 0o600)
            atomic_write(backup / 'existing', original, 0o640)
            records = [
                {'path': 'existing', 'original_sha256': digest(original), 'original_mode': 0o640, 'installed_sha256': digest(installed)},
                {'path': 'new', 'original_sha256': None, 'original_mode': None, 'installed_sha256': digest(installed)},
            ]
            (backup / 'manifest.json').write_text(json.dumps(records))
            result = rollback(home, backup)
            self.assertEqual(result['restored'], 2)
            self.assertEqual((home / 'existing').read_bytes(), original)
            self.assertEqual((home / 'existing').stat().st_mode & 0o777, 0o640)
            self.assertFalse((home / 'new').exists())

    def test_changed_destination_blocks_entire_rollback(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp).resolve()
            backup = home / '.local/state/praiseassistant/install-backups/test'
            backup.mkdir(parents=True)
            atomic_write(home / 'existing', b'new-user-work', 0o600)
            atomic_write(backup / 'existing', b'original', 0o600)
            (backup / 'manifest.json').write_text(json.dumps([{'path': 'existing', 'original_sha256': digest(b'original'), 'original_mode': 0o600, 'installed_sha256': digest(b'installed')}]))
            with self.assertRaises(ValueError):
                rollback(home, backup)
            self.assertEqual((home / 'existing').read_bytes(), b'new-user-work')

    def test_destination_symlink_escape_is_refused(self):
        with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryDirectory() as outside:
            home = Path(temp).resolve()
            (home / 'linked').symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                safe(home, 'linked/owned')
            with self.assertRaises(ValueError):
                safe(home, '../outside')


if __name__ == '__main__':
    unittest.main()
