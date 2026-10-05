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

"""The validation verdict must have a way back out of the session.

The agent has no Write tool: it returns a ``ValidationOutput`` and the host writes
``validation_report.json`` / ``synthesized_gates.json``. That needs the Claude SDK to
be told an output schema, which is what these tests pin. A streaming session without
``output_format`` returns free-form text, the host writes nothing, and the run reports
UNVERIFIABLE with no indication why -- the exact regression test 6 guards.

Offline and deterministic: no network, no LLM, no subprocess.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from vvaharness.backends.harness import HarnessResult, OneShotOptions, StreamingOptions
from vvaharness.models import Decision, Provenance
from vvaharness.backends.harness.claude.options import (
    _resolve_output_schema,
    _sanitize_schema,
    build_oneshot_sdk_options,
    build_streaming_sdk_options,
)
from vvaharness.backends.harness.claude.translate import translate_result
from vvaharness.validation.config import load_config
from vvaharness.validation.config.settings import _ASSETS_ROOT
from vvaharness.validation.constants.artifacts import SYNTHESIZED_GATES_FILENAME
from vvaharness.validation.constants.policy import (
    DEFAULT_ALLOWED_OUTPUT_FILES,
    VALIDATION_POLICY,
)
from vvaharness.validation.io._host_score import (
    load_synthesized_gates,
    verdict_for,
)
from vvaharness.validation.models import Manifest
from vvaharness.validation.models.output import ValidationOutput
from vvaharness.validation.session.launcher import (
    _failure_reason,
    _load_system_prompt,
    _synthesis_section,
    _synthesizes_gates_on_host,
    _write_validation_outputs,
    build_validation_options,
)


def _options(workspace: Path) -> StreamingOptions:
    return build_validation_options(
        config=load_config(),
        manifest=Manifest(case_id="TEST-1", session_id="s1"),
        workspace=workspace,
        output_dir=workspace / "out",
        system_prompt=None,
    )


def _cfg(via: str) -> SimpleNamespace:
    return SimpleNamespace(
        agent=SimpleNamespace(via=via),
        paths=SimpleNamespace(prompts_dir=_ASSETS_ROOT / "prompts"),
    )


_PATH_CFG = SimpleNamespace(system_prompt_file="system.md")


# Schema resolution

def test_no_schema_when_neither_field_is_set(tmp_path: Path) -> None:
    options = StreamingOptions(model="m", cwd=tmp_path)
    assert _resolve_output_schema(options) is None


def test_explicit_output_schema_wins_over_response_model(tmp_path: Path) -> None:
    options = StreamingOptions(
        model="m",
        cwd=tmp_path,
        output_schema={"type": "object", "title": "Explicit"},
        response_model=ValidationOutput,
    )
    assert _resolve_output_schema(options) == {"type": "object", "title": "Explicit"}


def test_schema_derived_from_response_model(tmp_path: Path) -> None:
    options = StreamingOptions(model="m", cwd=tmp_path, response_model=ValidationOutput)
    assert _resolve_output_schema(options) == ValidationOutput.model_json_schema()


def test_non_pydantic_response_model_degrades_to_none(tmp_path: Path) -> None:
    """``response_model`` is typed ``type``, so a plain class must not raise."""
    options = StreamingOptions(model="m", cwd=tmp_path, response_model=int)
    assert _resolve_output_schema(options) is None


def test_sanitize_strips_the_dialect_declaration_only() -> None:
    """A ``$schema`` key fails the CLI at startup; ``$defs``/``$ref`` resolve fine."""
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "$defs": {"Inner": {"type": "string"}},
        "properties": {"a": {"$ref": "#/$defs/Inner"}},
    }
    out = _sanitize_schema(schema)
    assert "$schema" not in out
    assert out["$defs"] == {"Inner": {"type": "string"}}
    assert out["properties"] == {"a": {"$ref": "#/$defs/Inner"}}


# The regression: a streaming validation session must request structured output

def test_streaming_validation_options_request_structured_output(tmp_path: Path) -> None:
    sdk_opts = build_streaming_sdk_options(_options(tmp_path))
    assert sdk_opts.output_format == {
        "type": "json_schema",
        "schema": ValidationOutput.model_json_schema(),
    }


def test_oneshot_options_request_structured_output(tmp_path: Path) -> None:
    options = OneShotOptions(model="m", cwd=tmp_path, response_model=ValidationOutput)
    sdk_opts = build_oneshot_sdk_options(options)
    assert sdk_opts.output_format == {
        "type": "json_schema",
        "schema": ValidationOutput.model_json_schema(),
    }


def test_streaming_options_omit_output_format_when_no_schema(tmp_path: Path) -> None:
    sdk_opts = build_streaming_sdk_options(StreamingOptions(model="m", cwd=tmp_path))
    assert sdk_opts.output_format is None


# Tripwires on the schema the CLI has to accept

def test_validation_schema_declares_no_dialect() -> None:
    """Declaring a dialect makes the CLI reject the schema before the run starts."""
    assert "$schema" not in ValidationOutput.model_json_schema()


def _refs(node: object) -> set[str]:
    """Collect every ``$ref`` target name reachable in *node*."""
    if isinstance(node, dict):
        found = set()
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                found.add(value.rsplit("/", 1)[-1])
            else:
                found |= _refs(value)
        return found
    if isinstance(node, list):
        return set().union(*(_refs(item) for item in node)) if node else set()
    return set()


def test_every_ref_resolves_into_defs() -> None:
    schema = ValidationOutput.model_json_schema()
    refs = _refs(schema)
    assert refs, "expected the schema to use $defs/$ref"
    assert refs <= set(schema.get("$defs", {}))


# Failure diagnostics

def test_translate_result_carries_errors() -> None:
    message = SimpleNamespace(
        subtype="error_max_structured_output_retries",
        is_error=True,
        session_id="s1",
        result=None,
        structured_output=None,
        errors=["schema mismatch on findings[0]"],
        usage=None,
        total_cost_usd=None,
    )
    result = translate_result(message)[0]
    assert isinstance(result, HarnessResult)
    assert result.errors == ["schema mismatch on findings[0]"]


def test_failure_reason_names_the_subtype_and_errors() -> None:
    reason = _failure_reason(
        HarnessResult(
            subtype="error_max_structured_output_retries",
            errors=["did not match schema"],
        ),
        1,
    )
    assert "error_max_structured_output_retries" in reason
    assert "did not match schema" in reason
    assert "retries were exhausted" in reason or "retracted" in reason


def test_failure_reason_without_a_terminal_result() -> None:
    assert "no terminal result" in _failure_reason(None, 2)


# Per-backend gate synthesis

def test_only_deepagents_synthesizes_gates_on_the_host() -> None:
    assert _synthesizes_gates_on_host(_cfg("deepagents")) is True
    assert _synthesizes_gates_on_host(_cfg("sdk")) is False
    assert _synthesizes_gates_on_host(_cfg("cli")) is False


def test_synthesis_section_differs_by_backend() -> None:
    deep = _synthesis_section(_cfg("deepagents"))
    sdk = _synthesis_section(_cfg("sdk"))
    assert "empty list `[]`" in deep
    assert "Fill `synthesized_gates`" in sdk
    assert "Do NOT compute scores" in sdk


def test_system_prompt_carries_exactly_one_synthesis_section() -> None:
    for via in ("cli", "sdk", "deepagents"):
        prompt = _load_system_prompt(_cfg(via), _PATH_CFG)
        assert prompt is not None
        assert prompt.count("## Synthesis boundary") == 1, via


# The main agent's own gates must score

def _gate(name: str, status: str = "pass") -> dict[str, object]:
    return {"gate_name": name, "status": status, "summary": "s", "evidence": [], "details": ""}


GATE_NAMES = (
    "root_cause",
    "instance_coverage",
    "no_new_vulnerabilities",
    "security_best_practices",
)


def test_orchestrator_gates_score_end_to_end(tmp_path: Path) -> None:
    """With no host synthesis, what the orchestrator returned is what gets scored."""
    structured = {
        "target_jira_status": "Done",
        "findings": [{"tracking_id": "T-1", "finding_title": "t"}],
        "synthesized_gates": [
            {"tracking_id": "T-1", "gates": [_gate(n) for n in GATE_NAMES]}
        ],
    }
    _write_validation_outputs(tmp_path, structured)

    gates_file = tmp_path / SYNTHESIZED_GATES_FILENAME
    assert gates_file.exists()
    gates = load_synthesized_gates(tmp_path).get("T-1")
    verdict = verdict_for(None, gates, provenance=Provenance())
    assert verdict.decision is Decision.FIXED
    assert verdict.score == pytest.approx(1.0)
    # Every gate the orchestrator returned is carried onto the verdict, in the order given.
    assert tuple(gate.name for gate in verdict.gates) == GATE_NAMES


def test_empty_orchestrator_gates_fail_closed(tmp_path: Path) -> None:
    """The prompt's old `[]` mandate scores nothing without host synthesis."""
    _write_validation_outputs(
        tmp_path,
        {"target_jira_status": "In Progress", "findings": [], "synthesized_gates": []},
    )
    verdict = verdict_for(None, load_synthesized_gates(tmp_path).get("T-1"), provenance=Provenance())
    assert verdict.decision is Decision.INCONCLUSIVE
    # No gates reached the host, so there is no number to report -- not a zero-confidence claim.
    assert verdict.score is None
    assert verdict.gates == ()


# Policy

def test_validation_policy_grants_no_write() -> None:
    """The host persists artifacts; an agent-written report would be a self-report."""
    assert "Write" not in VALIDATION_POLICY.allowed_tools
    assert "Agent" in VALIDATION_POLICY.allowed_tools
    for denied in ("Edit", "NotebookEdit", "Bash"):
        assert denied in VALIDATION_POLICY.disallowed_tools


def test_allowed_output_files_kept_as_defence_in_depth() -> None:
    assert SYNTHESIZED_GATES_FILENAME in DEFAULT_ALLOWED_OUTPUT_FILES
    assert "validation_report.json" in DEFAULT_ALLOWED_OUTPUT_FILES
