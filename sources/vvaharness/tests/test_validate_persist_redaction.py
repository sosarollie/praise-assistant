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

"""Profile-specific S10/S11 defaults + persisted-log redaction guards (F34, F29)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

import vvaharness.config as harness_config
from vvaharness.validation.cli._run import _persist_session_log

_PROFILES = Path(__file__).resolve().parents[1] / "vvaharness" / "config" / "profiles"
# Canonical AWS example key — AKIA + 16 chars, matched by the redact() AWS-KEY rule.
_FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


@pytest.mark.parametrize("profile,enabled", [
    ("default.yaml", False),
    ("sdk.yaml", True),
    ("full.yaml", True),
    ("taint.yaml", False),
])
def test_profiles_declare_and_resolve_remediate_and_validate_defaults(
        profile: str, enabled: bool, monkeypatch) -> None:
    monkeypatch.setenv("VVAHARNESS_NO_LOCAL_CONFIG", "1")
    path = _PROFILES / profile
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    cfg = harness_config.load(path)
    for step in ("step_remediate", "step_validate"):
        assert raw[step]["enabled"] is enabled, f"{profile}: explicit {step} default"
        assert getattr(cfg, step).enabled is enabled, f"{profile}: resolved {step} default"


def test_default_profile_header_states_sdk_key_required() -> None:
    text = (_PROFILES / "default.yaml").read_text(encoding="utf-8")
    assert "No SDK API key is required" not in text
    assert "ANTHROPIC_SDK_API_KEY" in text


def _make_workspace(tmp_path: Path) -> Path:
    workspace = tmp_path / "ws"
    log_dir = workspace / "logging" / "orchestrator"
    log_dir.mkdir(parents=True)
    (log_dir / "session.jsonl").write_text(
        '{"event": "bash", "secret": "' + _FAKE_AWS_KEY + '"}\n', encoding="utf-8"
    )
    return workspace


def test_persisted_session_log_is_redacted(tmp_path: Path) -> None:
    workspace = _make_workspace(tmp_path)
    # The session log lands next to the finding's finding_case.json (loaded.path).
    finding_dir = tmp_path / "security-remediation" / "01_some-finding"
    finding_dir.mkdir(parents=True)
    report = SimpleNamespace(
        case_id="VULN-001",
        path=finding_dir / "finding_case.json",
    )

    dest = _persist_session_log(workspace, report)  # type: ignore[arg-type]  # duck-typed stub

    assert dest is not None
    assert dest == finding_dir / "validation_session_VULN-001.jsonl"
    persisted = dest.read_text(encoding="utf-8")
    assert _FAKE_AWS_KEY not in persisted, "AWS key leaked into persisted session log"
    assert "[REDACTED-AWS-KEY]" in persisted


def test_session_log_failure_leaves_no_unredacted_dest(tmp_path: Path) -> None:
    # N30: if the source cannot be read/decoded, no destination file is left behind. The raw
    # transcript is never copied to disk first, so a failure can't strand an unredacted artifact.
    workspace = tmp_path / "ws"
    log_dir = workspace / "logging" / "orchestrator"
    log_dir.mkdir(parents=True)
    # A directory in place of session.jsonl: exists() is True, but read_text() raises OSError.
    (log_dir / "session.jsonl").mkdir()
    finding_dir = tmp_path / "security-remediation" / "01_some-finding"
    finding_dir.mkdir(parents=True)
    report = SimpleNamespace(
        case_id="VULN-001",
        path=finding_dir / "finding_case.json",
    )

    dest = _persist_session_log(workspace, report)  # type: ignore[arg-type]  # duck-typed stub

    assert dest is None
    assert not (finding_dir / "validation_session_VULN-001.jsonl").exists()


def test_capture_transcript_hook_is_debug_gated() -> None:
    hook = (
        Path(__file__).resolve().parents[1]
        / "vvaharness" / "validation" / "claude_config" / "hooks" / "logging"
        / "capture_transcript.sh"
    )
    text = hook.read_text(encoding="utf-8")
    assert "VALIDATION_DEBUG_TRANSCRIPT" in text, "raw transcript hook must be opt-in"
