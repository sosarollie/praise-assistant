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

"""s0_seed rulepack resolution — must be local-path-only, never network."""
from __future__ import annotations

from types import SimpleNamespace

from vvaharness.pipeline.stages import s0_seed as s0
from vvaharness.rules import RULES_DIR


def _cfg(**kw):
    return SimpleNamespace(step0=SimpleNamespace(**kw))


def test_resolves_local_semgrep_subdirs_per_language(tmp_path):
    for d in ("java", "python", "go", "ruby"):
        (tmp_path / d).mkdir()
    packs = s0._resolve_rulepacks(
        _cfg(semgrep_rules_repo=str(tmp_path), rulepacks=[]),
        langs=["java", "python", "cobol"],   # cobol → no subdir → skipped
        rules_dir=RULES_DIR,
    )
    assert str(RULES_DIR / "sources.yaml") in packs       # vendored always-on
    assert str(tmp_path / "java") in packs
    assert str(tmp_path / "python") in packs
    assert all(not p.startswith("p/") for p in packs)     # no registry refs
    assert "cobol" not in " ".join(packs)


def test_registry_refs_are_rejected(tmp_path, capsys):
    packs = s0._resolve_rulepacks(
        _cfg(semgrep_rules_repo=None,
             rulepacks=["p/java", "r/python.flask", str(tmp_path)]),
        langs=["java"], rules_dir=RULES_DIR,
    )
    assert "p/java" not in packs and "r/python.flask" not in packs
    assert str(tmp_path) in packs
    err = capsys.readouterr().err
    assert "offline-only" in err


def test_missing_repo_warns_and_degrades(capsys):
    packs = s0._resolve_rulepacks(
        _cfg(semgrep_rules_repo="/does/not/exist", rulepacks=[]),
        langs=["java"], rules_dir=RULES_DIR,
    )
    assert packs == [str(RULES_DIR / "sources.yaml")]
    assert "does not exist" in capsys.readouterr().err


def test_cpp_falls_back_to_c_subdir(tmp_path):
    (tmp_path / "c").mkdir()                              # no cpp/ dir
    packs = s0._resolve_rulepacks(
        _cfg(semgrep_rules_repo=str(tmp_path), rulepacks=[]),
        langs=["cpp"], rules_dir=RULES_DIR,
    )
    assert str(tmp_path / "c") in packs


def test_parse_sarif_tags_sink_with_rule_cwe():
    """Gap-#2 wiring: SARIF driver.rules CWE tags must land on each Sink so
    s3→s4 can splice CweKB guidance into the confirm/refute prompt."""
    sarif = {"runs": [{
        "tool": {"driver": {"rules": [
            {"id": "java.sql.tainted-sql",
             "properties": {"tags": ["CWE-89", "OWASP-A03", "cwe-564: hql"]}},
        ]}},
        "results": [{
            "ruleId": "java.sql.tainted-sql",
            "message": {"text": "user input reaches Statement.executeQuery"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "src/Dao.java"},
                "region": {"startLine": 42,
                           "snippet": {"text": "stmt.executeQuery(q)"}},
            }}],
        }],
    }]}
    seed = s0._parse_sarif(sarif, in_scope={"src/Dao.java"})
    assert len(seed.unsafe_sinks) == 1
    sink = seed.unsafe_sinks[0]
    assert sink.file == "src/Dao.java" and sink.line == 42
    # Only CWE-prefixed tags survive (rule_cwe filter), OWASP-A03 dropped.
    assert sink.cwe == ["CWE-89", "cwe-564: hql"]
    assert seed.rule_cwe["java.sql.tainted-sql"] == sink.cwe
