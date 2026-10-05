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

"""Tests for user-configurable reviewer-persona tools (step_validate.allowed_tools).

Covers the full chain: profile step_validate.allowed_tools -> _apply_model_env (ValidateOverrides) ->
load_config (AgentConfig.validate_tools) -> load_agents(tools_override=) ->
SubagentDefinition.tools -> SDK AgentDefinition.tools. The key safety property is that
dropping Bash from the list removes it from every persona.
"""

from vvaharness.backends.harness.claude.options import _to_agent_definition
from vvaharness.validation.config import load_config
from vvaharness.validation.config.settings import _parse_tools
from vvaharness.validation.constants.artifacts import ENV_VALIDATE_TOOLS
from vvaharness.validation.subagents import load_agents

_PERSONAS = ("security-architect", "penetration-tester", "cross-repo-analyzer")


def test_override_without_bash_strips_bash_from_all_personas() -> None:
    ag = load_agents(list(_PERSONAS), tools_override=("Read", "Grep", "Glob"))
    for name in _PERSONAS:
        assert "Bash" not in (ag[name].tools or ()), f"{name} still has Bash"
        assert set(ag[name].tools or ()) == {"Read", "Grep", "Glob"}


def test_override_survives_into_sdk_agent_definition() -> None:
    ag = load_agents(["security-architect"], tools_override=("Read", "Grep", "Glob"))
    sdk_tools = _to_agent_definition(ag["security-architect"]).tools or []
    assert "Bash" not in sdk_tools
    assert "Read" in sdk_tools


# ── default (no override): personas keep their .md frontmatter set incl. fact tools ──
def test_no_override_keeps_frontmatter_tools() -> None:
    ag = load_agents(list(_PERSONAS))
    for name in _PERSONAS:
        assert "Bash" not in (ag[name].tools or ()), f"{name} should not have Bash"
        assert {"Read", "Grep", "Glob", "DiffTouched", "PatternScan"}.issubset(
            set(ag[name].tools or ())
        ), f"{name} missing read-only fact tools"


def test_validate_tools_in_overrides(tmp_path) -> None:
    from vvaharness.validation.cli._model import _apply_model_env
    cfg_path = tmp_path / "p.yaml"
    cfg_path.write_text(
        "models:\n  validate:\n    orchestrator: {id: gpt-5.5, via: deepagents}\n"
        "step_validate:\n  enabled: true\n  allowed_tools: [Read, Grep, Glob]\n",
        encoding="utf-8",
    )
    rc, overrides = _apply_model_env(str(cfg_path))
    assert rc == 0
    assert overrides["validate_tools"] == "Read,Grep,Glob"
    assert load_config(overrides=overrides).agent.validate_tools == ("Read", "Grep", "Glob")


def test_absent_tools_not_in_overrides(tmp_path) -> None:
    from vvaharness.validation.cli._model import _apply_model_env
    cfg_path = tmp_path / "p.yaml"
    cfg_path.write_text(
        "models:\n  validate:\n    orchestrator: {id: gpt-5.5, via: deepagents}\n"
        "step_validate:\n  enabled: true\n",
        encoding="utf-8",
    )
    rc, overrides = _apply_model_env(str(cfg_path))
    assert rc == 0
    assert "validate_tools" not in overrides


def test_env_var_no_longer_sets_validate_tools(monkeypatch) -> None:
    # validate_tools is override-or-default only now; setting the env var must be ignored.
    monkeypatch.setenv(ENV_VALIDATE_TOOLS, "Read,Grep")
    assert load_config().agent.validate_tools is None


def test_parse_tools_splits_strips_and_drops_empties() -> None:
    assert _parse_tools(" Read , Grep ,,Glob ") == ("Read", "Grep", "Glob")
    assert _parse_tools("") is None
    assert _parse_tools("   ") is None


def test_secret_pattern_scan_returns_safe_metadata_and_excludes_diff(tmp_path) -> None:
    from vvaharness.validation.tools.pattern_scanner import pattern_scan

    (tmp_path / "app.py").write_text(
        'db_config = os.environ["PASSWORD"]\n', encoding="utf-8"
    )
    diff_secret = "plaintext-secret-value"
    (tmp_path / "diff.patch").write_text(
        f'-api_key = "{diff_secret}"\n', encoding="utf-8"
    )
    clean = pattern_scan(tmp_path, "secret_exposure")
    assert clean[:-1] == []
    assert clean[-1] == {
        "kind": "summary",
        "pattern_set": "secret_exposure",
        "matches_seen": 0,
        "matches_returned": 0,
        "files_considered": 1,
        "files_scanned": 1,
        "files_too_large": 0,
        "files_unreadable": 0,
        "binary_files": 0,
        "bytes_scanned": len('db_config = os.environ["PASSWORD"]\n'),
        "truncated": False,
        "truncation_reasons": [],
        "limits": {
            "max_file_bytes": 512 * 1024,
            "max_total_bytes": 32 * 1024 * 1024,
            "max_files": 10_000,
            "max_matches_per_file": 50,
            "max_matches": 200,
        },
    }

    tree_secret = "remaining-secret-value"
    (tmp_path / "settings.py").write_text(
        f'client_secret = "{tree_secret}"\n', encoding="utf-8"
    )
    scan = pattern_scan(tmp_path, "secret_exposure")
    assert [(match["file"], match["line"]) for match in scan[:-1]] == [
        ("settings.py", 1)
    ]
    assert all("snippet" not in item for item in scan)
    assert diff_secret not in repr(scan)
    assert tree_secret not in repr(scan)
    assert scan[-1]["matches_seen"] == 1
    assert scan[-1]["truncated"] is False


def test_secret_pattern_scan_uses_s1_test_file_glob_exclusions(tmp_path) -> None:
    from vvaharness.validation.tools.pattern_scanner import pattern_scan

    (tmp_path / "src").mkdir()
    for relative in ("test_root.py", "src/service_test.py", "src/view.spec.ts"):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('api_key = "excluded-secret-value"\n', encoding="utf-8")
    (tmp_path / "src" / "service.py").write_text(
        'api_key = "production-secret-value"\n', encoding="utf-8"
    )

    scan = pattern_scan(tmp_path, "secret_exposure")

    assert [match["file"] for match in scan if match["kind"] == "match"] == [
        "src/service.py"
    ]
    assert scan[-1]["files_scanned"] == 1


def test_pattern_scan_bounds_files_and_results_with_explicit_signal(
    tmp_path, monkeypatch
) -> None:
    from vvaharness.validation.tools import pattern_scanner

    monkeypatch.setattr(pattern_scanner, "_MAX_FILE_BYTES", 128)
    monkeypatch.setattr(pattern_scanner, "_MAX_MATCHES_PER_FILE", 1)
    monkeypatch.setattr(pattern_scanner, "_MAX_MATCHES", 1)
    (tmp_path / "a.py").write_text(
        'api_key = "first-secret-value"\napi_key = "second-secret-value"\n',
        encoding="utf-8",
    )
    (tmp_path / "b.py").write_text(
        'api_key = "third-secret-value"\n', encoding="utf-8"
    )
    (tmp_path / "large.py").write_text("x" * 129, encoding="utf-8")

    scan = pattern_scanner.pattern_scan(tmp_path, "secret_exposure")
    summary = scan[-1]

    assert len(scan[:-1]) == 1
    assert summary["matches_seen"] == 3
    assert summary["matches_returned"] == 1
    assert summary["files_too_large"] == 1
    assert summary["truncated"] is True
    assert summary["truncation_reasons"] == [
        "file_size_limit", "per_file_match_limit", "overall_match_limit"
    ]
    assert all("snippet" not in item for item in scan)
    assert "secret-value" not in repr(scan)


def test_pattern_scan_counts_skipped_reads_against_the_total_budget(
    tmp_path, monkeypatch
) -> None:
    from vvaharness.validation.tools import pattern_scanner

    monkeypatch.setattr(pattern_scanner, "_MAX_FILE_BYTES", 8)
    monkeypatch.setattr(pattern_scanner, "_MAX_TOTAL_BYTES", 10)
    (tmp_path / "a.txt").write_bytes(b"\x00abcde")
    (tmp_path / "b.txt").write_bytes(b"oversized")
    (tmp_path / "c.py").write_text(
        'api_key = "must-not-be-read"\n', encoding="utf-8"
    )

    scan = pattern_scanner.pattern_scan(tmp_path, "secret_exposure")
    summary = scan[-1]

    assert scan[:-1] == []
    assert summary["bytes_scanned"] == 10
    assert summary["files_considered"] == 2
    assert summary["files_scanned"] == 0
    assert summary["binary_files"] == 1
    assert summary["files_too_large"] == 1
    assert summary["truncated"] is True
    assert summary["truncation_reasons"] == [
        "file_size_limit", "binary_files", "overall_byte_limit"
    ]
    assert "must-not-be-read" not in repr(scan)


def test_pattern_scan_signals_overall_file_and_byte_limits(tmp_path, monkeypatch) -> None:
    from vvaharness.validation.tools import pattern_scanner

    (tmp_path / "app.py").write_text("safe = True\n", encoding="utf-8")
    monkeypatch.setattr(pattern_scanner, "_MAX_TOTAL_BYTES", 0)
    byte_limited = pattern_scanner.pattern_scan(tmp_path, "secret_exposure")[-1]
    assert byte_limited["bytes_scanned"] == 0
    assert byte_limited["truncated"] is True
    assert byte_limited["truncation_reasons"] == ["overall_byte_limit"]

    monkeypatch.setattr(pattern_scanner, "_MAX_FILES", 0)
    file_limited = pattern_scanner.pattern_scan(tmp_path, "secret_exposure")[-1]
    assert file_limited["files_considered"] == 0
    assert file_limited["truncated"] is True
    assert file_limited["truncation_reasons"] == ["overall_file_limit"]
