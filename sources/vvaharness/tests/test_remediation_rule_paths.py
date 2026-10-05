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

"""Resolution and persistence tests for remediation input rules."""
from __future__ import annotations

from vvaharness.remediation_agent import rule_paths


def test_configured_input_directory_resolves_rules(monkeypatch, tmp_path):
    inputs = tmp_path / "custom-inputs"
    inputs.mkdir()
    for name in rule_paths.RULE_FILES:
        (inputs / name).write_text("rules: []\n", encoding="utf-8")
    settings = tmp_path / "settings.json"
    monkeypatch.setenv("VVAHARNESS_SETTINGS_FILE", str(settings))
    rule_paths.save_inputs_dir(inputs)
    monkeypatch.setattr(
        rule_paths, "candidate_inputs_dirs",
        lambda _package_file: (tmp_path / "missing", inputs),
    )

    assert not rule_paths.missing_rules(__file__)
    assert rule_paths.locate_rule("remediation_policy.yaml", __file__) == (
        inputs / "remediation_policy.yaml")


def test_save_preserves_other_user_settings(monkeypatch, tmp_path):
    settings = tmp_path / "settings.json"
    settings.write_text('{"other": true}\n', encoding="utf-8")
    monkeypatch.setenv("VVAHARNESS_SETTINGS_FILE", str(settings))
    inputs = tmp_path / "inputs"
    inputs.mkdir()

    rule_paths.save_inputs_dir(inputs)

    text = settings.read_text(encoding="utf-8")
    assert '"other": true' in text
    assert str(inputs.resolve()) in text
