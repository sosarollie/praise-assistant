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

"""
CWE knowledge-base loader (vvaharness.rules.CweKB) — load/merge/filter/render.
"""
from __future__ import annotations

import textwrap

import pytest

from vvaharness.rules import RULES_DIR, CweKB, _filter_lang, _norm_cwe

# helpers

def _write(d, name, body):
    (d / name).write_text(textwrap.dedent(body), encoding="utf-8")


# unit: normalisation + lang filter

@pytest.mark.parametrize("raw,want", [
    ("CWE-89", "CWE-89"), ("cwe-089", "CWE-89"), ("CWE 89", "CWE-89"),
    ("CWE-89: SQL Injection", "CWE-89"),
    ("nope", None), (None, None), ("", None), (89, None),
])
def test_norm_cwe(raw, want):
    assert _norm_cwe(raw) == want


def test_filter_lang_keeps_unprefixed_and_matching():
    items = ["any-lang item",
             "java: PreparedStatement",
             "python: cursor.execute",
             "free text: with a colon and more"]   # >15-char head → NOT a tag
    assert _filter_lang(items, "java") == [
        "any-lang item", "PreparedStatement",
        "free text: with a colon and more"]
    assert _filter_lang(items, "python") == [
        "any-lang item", "cursor.execute",
        "free text: with a colon and more"]
    # lang=None keeps everything (prefix stripped)
    assert _filter_lang(items, None) == [
        "any-lang item", "PreparedStatement", "cursor.execute",
        "free text: with a colon and more"]


# shipped KB sanity — every committed *.kb.yaml must parse + be well-formed

def test_shipped_kb_loads_and_is_well_formed():
    kb = CweKB.load(RULES_DIR)       # explicit dir → bypass class cache
    assert len(kb) > 0, "cwe_kb.yaml shipped no entries"
    assert "CWE-89" in kb and "CWE-79" in kb and "CWE-502" in kb
    # every shipped file has valid `cwe:` on every entry
    for p in CweKB._kb_files(RULES_DIR):
        for e in CweKB._read(p):
            assert _norm_cwe(e.get("cwe")), f"{p.name}: entry missing cwe: {e!r}"


def test_shipped_kb_lang_filter_on_sqli():
    ctx = CweKB.load(RULES_DIR).for_cwes("CWE-89", lang="java")
    assert any("PreparedStatement" in s for s in ctx["sanitizers"])
    assert not any("python" in s.lower() for s in ctx["sinks"])
    # generic (unprefixed) sanitizer survives lang filter
    assert any("Parameterised" in s or "Parameterized" in s
               for s in ctx["sanitizers"])


# merge: builtin + extension corpus, aliases, dedup

def test_extension_corpus_is_auto_merged(tmp_path):
    _write(tmp_path, "cwe_kb.yaml", """
        entries:
          - cwe: CWE-89
            title: SQL Injection
            origin: builtin
            aliases: [CWE-564]
            sanitizers: ["Parameterised query", "java: PreparedStatement"]
            non_sanitizers: ["addslashes"]
    """)
    _write(tmp_path, "findsecbugs.kb.yaml", """
        entries:
          - cwe: CWE-89
            origin: findsecbugs
            sinks: ["java: Statement.executeQuery"]
            sanitizers: ["Parameterised query"]      # duplicate → deduped
          - cwe: CWE-78
            title: OS Command Injection
            origin: findsecbugs
            sinks: ["java: Runtime.exec"]
    """)
    kb = CweKB.load(tmp_path)
    assert len(kb) >= 3                       # 89, 564 (alias), 78
    assert "CWE-564" in kb                    # alias resolves
    ctx = kb.for_cwes(["CWE-89"], lang="java")
    assert ctx["origin"] == ["builtin", "findsecbugs"]
    assert ctx["sanitizers"].count("Parameterised query") == 1   # deduped
    assert "Statement.executeQuery" in ctx["sinks"]
    # alias + canonical in one query → slot counted once, not twice
    ctx2 = kb.for_cwes(["CWE-89", "CWE-564"], lang="java")
    assert ctx2["sanitizers"] == ctx["sanitizers"]


def test_unknown_cwe_and_missing_dir_degrade_gracefully(tmp_path):
    kb = CweKB.load(tmp_path)                 # empty dir
    assert len(kb) == 0
    assert kb.prompt_block(["CWE-89"]) == ""
    assert kb.for_cwes(None)["sanitizers"] == []
    # nonexistent dir
    assert len(CweKB.load(tmp_path / "nope")) == 0


def test_malformed_file_is_skipped_not_fatal(tmp_path, capsys):
    _write(tmp_path, "cwe_kb.yaml", """
        entries:
          - cwe: CWE-22
            sanitizers: ["realpath + prefix check"]
    """)
    _write(tmp_path, "broken.kb.yaml", "entries: [this: is: not: valid: yaml")
    kb = CweKB.load(tmp_path)
    assert "CWE-22" in kb                     # good file still loaded
    assert "WARN" in capsys.readouterr().err  # bad file warned, not raised


# prompt_block rendering

def test_prompt_block_shape():
    kb = CweKB.load(RULES_DIR)
    block = kb.prompt_block(["CWE-89"], lang="python")
    assert block.startswith("TAINT KB — SQL Injection")
    assert "SANITIZERS" in block and "NON-SANITIZERS" in block
    assert "REFUTE" in block
    assert "cursor.execute" in block          # python sink survived filter
    assert "PreparedStatement" not in block   # java-only item filtered out
    # unknown CWE → empty so s4 splices a no-op
    assert kb.prompt_block(["CWE-99999"]) == ""
    assert kb.prompt_block([]) == ""


# s4 integration — confirm/refute prompt carries the KB block

def test_s4_confirm_refute_prompt_includes_kb_block():
    from vvaharness.models import Chunk, ChunkSize, ContextPackage
    from vvaharness.pipeline.stages import s4_deepdive as s4

    ctx = ContextPackage(repo_root=".", language="python")
    chunk = Chunk(
        id="taint-01", size=ChunkSize.SMALL, files=["a.py"],
        hypothesis="x", path_funcs=["a.py::h", "a.py::sink"],
        source_ref="a.py::h", sink_ref="a.py:10",
        sink_cwe=["CWE-89"], languages=["python"],
    )
    p = s4._build_confirm_refute_prompt(chunk, ctx, "<CODE>")
    assert "TAINT KB — SQL Injection" in p
    assert "NON-SANITIZERS" in p
    # unknown CWE → no KB block, prompt still well-formed
    chunk.sink_cwe = ["CWE-99999"]
    p2 = s4._build_confirm_refute_prompt(chunk, ctx, "<CODE>")
    assert "TAINT KB" not in p2
    assert "CANDIDATE PATH" in p2 and "<CODE>" in p2
