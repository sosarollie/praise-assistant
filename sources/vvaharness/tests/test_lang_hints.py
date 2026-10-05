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

"""Coverage-presence guards for detector prompt hints (lang.hints).

These lock the weakness classes that were previously under-covered so a future
refactor can't silently drop them. They assert the guidance TEXT is present —
they do not (and cannot) assert detection quality.
"""
from vvaharness.lang.hints import LANG_HINTS, SPECIALIST_HINTS, detect_languages


def test_logic_bug_covers_indexof_sentinel_idiom():
    body = SPECIALIST_HINTS["logic-bug"]
    assert "indexOf" in body
    assert "== -1" in body


def test_access_control_blocks_hardcoded_constant_idor():
    body = SPECIALIST_HINTS["access-control"]
    assert "HARDCODED" in body
    assert "bounded blast radius" in body


def test_access_control_covers_destructive_bulk_ops():
    body = SPECIALIST_HINTS["access-control"]
    assert "Destructive bulk operations" in body


def test_python_and_java_cover_xpath_injection():
    assert "XPath injection" in LANG_HINTS["python"]
    assert "XPath injection" in LANG_HINTS["java"]


def test_injection_specialist_hint_present_and_covers_key_classes():
    body = SPECIALIST_HINTS["injection"]
    # HARD GATE preamble must remain present — every specialist follows this
    # pattern and the s6 verifier reads it as its ground rules.
    assert "HARD GATE" in body
    # A representative sink from each major injection class this lens owns.
    assert "cursor.execute" in body        # SQLi
    assert "subprocess" in body            # OS command
    assert "DirContext.search" in body     # LDAP
    assert "XPath" in body                 # XPath
    assert "DocumentBuilderFactory" in body  # XXE
    assert "SSRF" in body
    assert "Path traversal".casefold() in body.casefold() or "PATH TRAVERSAL" in body
    assert "SSTI" in body
    assert "open redirect".casefold() in body.casefold() or "OPEN REDIRECT" in body
    assert "CRLF" in body                  # header injection
    assert "ReDoS" in body
    # Enumeration rule keeps the specialist from collapsing distinct sinks.
    assert "ENUMERATION RULE" in body


def test_cobol_copy_statement_does_not_reclassify_python(tmp_path):
    root = tmp_path / "repo"
    path = root / "mvs_code" / "copy_module.py"
    path.parent.mkdir(parents=True)
    path.write_text('COPY thing.\nprint("still python")\n', encoding="utf-8")

    assert detect_languages(["mvs_code/copy_module.py"], repo_root=root) == ["python"]
