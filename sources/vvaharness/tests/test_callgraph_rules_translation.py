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

from vvaharness.pipeline.stages.callgraph_engine._rules import _spec_from_rule


def test_semgrep_translation_keeps_pattern_coverage_metadata():
    rule = {
        "id": "py-mixed-patterns",
        "languages": ["python"],
        "metadata": {"cwe": "CWE-78", "sink_kind": "cmd"},
        "patterns": [
            {"pattern": "os.system(...)"},
            {"pattern": "$X.execute(...)"},
            {"pattern-regex": "dangerous.*"},
        ],
    }

    specs = _spec_from_rule(rule, "sink")
    assert specs
    spec = specs[0]

    assert spec.origin == "semgrep"
    assert spec.total_pattern_leaves == 2
    assert "os.system(...)" in spec.parsed_pattern_leaves
    assert "$X.execute(...)" in spec.dropped_pattern_leaves
    assert "partial-pattern-coverage" in spec.translation_flags
    assert "nested-patterns" in spec.translation_flags
    assert "regex-patterns" in spec.translation_flags


def test_semgrep_unparseable_rule_is_dropped():
    rule = {
        "id": "py-only-regex",
        "languages": ["python"],
        "metadata": {"cwe": "CWE-79", "sink_kind": "xss"},
        "patterns": [
            {"pattern": "$VAR"},
            {"pattern-not": "safe_render(...)"},
        ],
    }

    specs = _spec_from_rule(rule, "sink")
    assert specs == []
