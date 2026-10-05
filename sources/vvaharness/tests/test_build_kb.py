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

"""rules.build_kb — corpus extractors emit *.kb.yaml that CweKB can load."""
from __future__ import annotations

import hashlib
import json
import textwrap
import time

import yaml

from vvaharness.rules import CweKB
from vvaharness.rules import build_kb as bk
from vvaharness.rules.generic_pack import write_generic_kb


def _w(p, body):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(body), encoding="utf-8")


def test_extract_semgrep_taint_rule(tmp_path):
    _w(tmp_path / "python" / "sqli.yaml", """
        rules:
          - id: py-sqli
            mode: taint
            languages: [python]
            metadata: {cwe: "CWE-89: SQL Injection"}
            pattern-sources: [{pattern: "flask.request.$X"}]
            pattern-sinks:   [{pattern: "$CUR.execute(...)"}]
            pattern-sanitizers: [{pattern: "int(...)"}]
          - id: ignored
            languages: [python]
            # NB: string below is a semgrep PATTERN literal (fixture data),
            # not an eval() call — nothing here is executed.
            pattern: "eval(...)"        # not taint-mode → skipped
    """)
    entries = bk.extract_semgrep(tmp_path)
    assert len(entries) == 1
    e = entries[0]
    assert e["cwe"] == "CWE-89" and e["origin"] == "semgrep"
    assert e["sinks"] == ["python: execute()"]       # metavars/ellipsis stripped
    assert e["sanitizers"] == ["python: int()"]


def test_extract_findsecbugs_sink_file(tmp_path):
    _w(tmp_path / "plugin" / "src" / "main" / "resources" /
       "injection-sinks" / "sql-jdbc.txt", """
        # comment
        java/sql/Statement.executeQuery(Ljava/lang/String;)Ljava/sql/ResultSet;:0
        org/hibernate/Session.createSQLQuery(Ljava/lang/String;):0
    """)
    entries = bk.extract_findsecbugs(tmp_path)
    assert len(entries) == 1
    e = entries[0]
    assert e["cwe"] == "CWE-89" and e["origin"] == "findsecbugs"
    assert "java: java.sql.Statement.executeQuery" in e["sinks"]
    assert "java: org.hibernate.Session.createSQLQuery" in e["sinks"]


def test_extract_codeql_qll(tmp_path):
    _w(tmp_path / "java" / "ql" / "lib" / "semmle" / "code" / "java" /
       "security" / "CWE-079" / "Xss.qll", '''
        class XssSink extends Sink {
          XssSink() { this.getMethod().hasName("getWriter") and x = "println" }
        }
        class HtmlSanitizer extends Sanitizer {
          HtmlSanitizer() { x = "org.owasp.encoder.Encode.forHtml" }
        }
    ''')
    entries = bk.extract_codeql(tmp_path)
    assert len(entries) == 1
    e = entries[0]
    assert e["cwe"] == "CWE-79" and e["origin"] == "codeql"
    assert "java: println" in e["sinks"] or "java: getWriter" in e["sinks"]
    assert "java: org.owasp.encoder.Encode.forHtml" in e["sanitizers"]


def test_extract_codeql_qll_malformed_header_is_linear():
    malformed = "class Broken extends Sink" + " " * 100_000 + "!"
    valid = '''
class GoodSink extends Sink {
  GoodSink() { x = "executeQuery" }
}
'''

    started = time.perf_counter()
    classes = list(bk._iter_ql_classes(malformed + valid))
    elapsed = time.perf_counter() - started

    assert classes == [("Sink", '\n  GoodSink() { x = "executeQuery" }')]
    assert elapsed < 0.5


def test_round_trip_all_three_into_cwe_kb(tmp_path):
    # minimal fixture for each corpus
    sg = tmp_path / "semgrep-rules"
    _w(sg / "java" / "x.yaml", """
        rules:
          - id: j
            mode: taint
            languages: [java]
            metadata: {cwe: ["CWE-89"]}
            pattern-sinks: [{pattern: "Statement.executeQuery(...)"}]
            pattern-sanitizers: [{pattern: "PreparedStatement.setString(...)"}]
    """)
    fsb = tmp_path / "find-sec-bugs"
    _w(fsb / "injection-sinks" / "command.txt",
       "java/lang/Runtime.exec(Ljava/lang/String;):0\n")
    cql = tmp_path / "codeql"
    _w(cql / "java" / "security" / "CWE-022" / "Path.qll", '''
        class PathSanitizer extends Sanitizer { P() { x = "getCanonicalPath" }
        }
    ''')

    out = tmp_path / "rules"
    for name, src in (("semgrep", sg), ("findsecbugs", fsb), ("codeql", cql)):
        bk.write_kb(name, bk.EXTRACTORS[name](src), out)

    kb = CweKB.load(out)
    assert "CWE-89" in kb and "CWE-78" in kb and "CWE-22" in kb

    j89 = kb.for_cwes("CWE-89", lang="java")
    assert "semgrep" in j89["origin"]
    assert any("PreparedStatement.setString" in s for s in j89["sanitizers"])

    j78 = kb.for_cwes("CWE-78", lang="java")
    assert "findsecbugs" in j78["origin"]
    assert any("Runtime.exec" in s for s in j78["sinks"])

    j22 = kb.for_cwes("CWE-22", lang="java")
    assert "codeql" in j22["origin"]
    assert any("getCanonicalPath" in s for s in j22["sanitizers"])

    # prompt block cites all three origins when merged on one CWE
    block = kb.prompt_block(["CWE-89", "CWE-78", "CWE-22"], lang="java")
    assert "semgrep" in block and "findsecbugs" in block and "codeql" in block


def test_cli_requires_at_least_one_corpus():
    import pytest
    with pytest.raises(SystemExit):
        bk.main([])


def test_write_generic_kb_creates_starter_pack(tmp_path):
  out = write_generic_kb(tmp_path)
  parsed = yaml.safe_load(out.read_text(encoding="utf-8"))
  assert out.name == "generic.kb.yaml"
  assert "entries" in parsed and len(parsed["entries"]) >= 10
  assert any(entry["origin"] == "generic" for entry in parsed["entries"])


def test_cli_generic_out_writes_without_corpus_clones(tmp_path):
  out = tmp_path / "generic.kb.yaml"
  rc = bk.main(["--generic-out", str(out)])
  assert rc == 0
  parsed = yaml.safe_load(out.read_text(encoding="utf-8"))
  assert any(entry["cwe"] == "CWE-89" for entry in parsed["entries"])


def test_prepare_callgraph_rules_filters_to_python_java():
  rules = [
    {
      "id": "r1",
      "languages": ["python", "javascript"],
      "metadata": {"cwe": "CWE-89", "ep_kind": "network"},
      "pattern": "flask.request.$X",
    },
    {
      "id": "r2",
      "languages": ["go"],
      "metadata": {"cwe": "CWE-89", "ep_kind": "network"},
      "pattern": "req.URL.Query()",
    },
  ]
  out = bk._prepare_callgraph_rules(
    rules,
    role="source",
    callgraph_langs=frozenset({"python", "java"}),
    strict=True,
  )
  assert len(out) == 1
  assert out[0]["languages"] == ["python"]


def test_prepare_callgraph_rules_strict_sink_metadata():
  import pytest
  bad_sink = {
    "id": "sink-missing-cwe",
    "languages": ["java"],
    "metadata": {"sink_kind": "sql"},
    "pattern": "$X.execute(...)",
  }
  with pytest.raises(ValueError):
    bk._prepare_callgraph_rules(
      [bad_sink],
      role="sink",
      callgraph_langs=frozenset({"python", "java"}),
      strict=True,
    )


def test_prepare_callgraph_rules_non_strict_defaults_metadata():
  bad_source = {
    "id": "src-missing-meta",
    "languages": ["python"],
    "metadata": {},
    "pattern": "request.args.get(...)",
  }
  out = bk._prepare_callgraph_rules(
    [bad_source],
    role="source",
    callgraph_langs=frozenset({"python", "java"}),
    strict=False,
  )
  assert len(out) == 1
  meta = out[0]["metadata"]
  assert meta["cwe"] == "CWE-20"
  assert meta["ep_kind"] == "network"


def test_artifact_provenance_contains_core_fields():
  rules = [{"id": "r1", "languages": ["python"], "pattern": "request.args.get(...)"}]
  prov = bk._artifact_provenance(
    artifact_type="sources",
    rules=rules,
    callgraph_langs=frozenset({"python", "java"}),
    strict_callgraph=True,
  )
  expected = hashlib.sha256(
    json.dumps(rules, sort_keys=True, separators=(",", ":")).encode("utf-8")
  ).hexdigest()
  assert prov["artifact_type"] == "sources"
  assert prov["builder_version"] == bk._VVAH_VERSION
  assert prov["strict_callgraph"] is True
  assert prov["callgraph_languages"] == ["java", "python"]
  assert prov["artifact_sha256"] == expected
  assert "generated_at_utc" in prov


def test_write_sources_yaml_includes_provenance_block(tmp_path):
  out = tmp_path / "sources.generated.yaml"
  rules = [{"id": "r1", "languages": ["python"], "pattern": "request.args.get(...)"}]
  prov = {"artifact_type": "sources", "builder_version": "x"}
  bk.write_sources_yaml(rules, out, provenance=prov)
  parsed = yaml.safe_load(out.read_text(encoding="utf-8"))
  assert parsed["rules"] == rules
  assert parsed["vvah_artifact"] == prov


def test_parse_lang_list_default_matches_runtime_plugins():
  langs = bk._parse_lang_list("")
  assert langs == frozenset({"python", "java", "javascript", "typescript", "go", "csharp"})


def test_prepare_callgraph_rules_strict_defaults_reject_missing_cwe():
  bad_rule = {
    "id": "r-missing-cwe",
    "languages": ["python"],
    "metadata": {"ep_kind": "network"},
    "pattern": "request.args.get(...)",
  }
  import pytest
  with pytest.raises(ValueError):
    bk._prepare_callgraph_rules(
      [bad_rule],
      role="source",
      callgraph_langs=bk._parse_lang_list(""),
      strict=True,
    )
