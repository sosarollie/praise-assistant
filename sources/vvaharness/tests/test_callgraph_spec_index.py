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

"""F05: the spec index must be a pure pre-filter — the spec `_match_call`
selects through the index must be byte-identical to the one a linear scan of the
full spec list would select, for every call shape."""
from __future__ import annotations

from vvaharness.pipeline.stages.callgraph_engine._rules import MatchSpec
from vvaharness.pipeline.stages.callgraph_engine._scan import (
    _build_spec_index,
    _match_call,
)


def _qualified(rule_id, package, class_name, method, lang="java", cwe="CWE-89"):
    return MatchSpec(
        rule_id=rule_id,
        role="sink",
        origin="codeql",
        cwe=cwe,
        kind="sql",
        languages=frozenset({lang}),
        package=package,
        class_name=class_name,
        top_class=class_name.split(".")[-1],
        methods=frozenset({method}),
    )


def _module_attr(rule_id, module, name, lang="python", cwe="CWE-78"):
    return MatchSpec(
        rule_id=rule_id,
        role="sink",
        origin="semgrep",
        cwe=cwe,
        kind="command",
        languages=frozenset({lang}),
        module_attr_module=module,
        module_attr_names=frozenset({name}),
    )


def _linear(receiver, method, imports, specs, language):
    """Reference: the original un-indexed scan over the whole list."""
    for spec in specs:
        hit = _match_call(receiver, method, imports, [spec], language)
        if hit is not None:
            return hit
    return None


def _corpus():
    # Deliberately overlapping: two java rules share the method name
    # "executeQuery" so first-match order matters; a python module.attr rule
    # shares the attr name "run" with a java rule to exercise per-language
    # partitioning.
    return [
        _qualified("java.sql.exec.A", "java.sql", "Statement", "executeQuery"),
        _qualified("java.sql.exec.B", "javax.persistence", "Query", "executeQuery"),
        _qualified("java.rt.exec", "java.lang", "Runtime", "run"),
        _module_attr("py.os.system", "os", "system"),
        _module_attr("py.subprocess.run", "subprocess", "run"),
        _qualified("cs.sql.exec", "System.Data", "SqlCommand", "ExecuteReader",
                   lang="csharp"),
    ]


def test_index_matches_linear_scan_across_call_shapes():
    specs = _corpus()
    index = _build_spec_index(specs)

    cases = [
        # (receiver, method, imports, language)
        ("stmt", "executeQuery", {"stmt": "java.sql.Statement"}, "java"),
        ("q", "executeQuery", {"q": "javax.persistence.Query"}, "java"),
        ("stmt", "executeQuery", {"stmt": "com.acme.Statement"}, "java"),
        ("os", "system", {}, "python"),
        ("subprocess", "run", {}, "python"),
        ("r", "run", {"r": "java.lang.Runtime"}, "java"),
        ("cmd", "ExecuteReader", {"cmd": "System.Data.SqlCommand"}, "csharp"),
        # Non-matches / wrong language must both return None.
        ("os", "system", {}, "java"),
        ("stmt", "unknownMethod", {"stmt": "java.sql.Statement"}, "java"),
        ("", "executeQuery", {}, "java"),
    ]

    for receiver, method, imports, language in cases:
        candidates = index.get(language, {}).get(method, ())
        indexed = _match_call(receiver, method, imports, candidates, language)
        linear = _linear(receiver, method, imports, specs, language)
        got = indexed.rule_id if indexed else None
        want = linear.rule_id if linear else None
        assert got == want, (receiver, method, language, got, want)


def test_index_preserves_first_match_order():
    specs = _corpus()
    index = _build_spec_index(specs)
    # Both java executeQuery rules are viable when the import resolves under
    # both packages is impossible, but order still decides among candidates that
    # each fully qualify; assert the candidate list keeps original order.
    cands = index["java"]["executeQuery"]
    assert [s.rule_id for s in cands] == ["java.sql.exec.A", "java.sql.exec.B"]
