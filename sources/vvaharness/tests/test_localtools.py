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

"""Unit tests for vvaharness.backends.llm.tools.

Security focus: the path jail must confine Read/Glob/Grep to a single repo
root so prompt-injected paths cannot exfiltrate sibling files. These tests
build a tmp_path repo with a sibling SECRET file and assert it is never
reachable. Fully offline/deterministic: no network, no LLM, no subprocess.
"""
from pathlib import Path

import pytest

from vvaharness.backends.llm import tools as lt

# Fixtures: a repo root with an out-of-root sibling secret.

@pytest.fixture
def repo(tmp_path):
    """Create `<tmp>/repo` with files, plus a SIBLING secret outside it.

    Layout:
        <tmp>/secret.txt              <- MUST never be reachable
        <tmp>/repo/                   <- jail root
        <tmp>/repo/a.txt
        <tmp>/repo/sub/b.java
        <tmp>/repo/sub/c.py
    """
    root = tmp_path / "repo"
    (root / "sub").mkdir(parents=True)
    (root / "a.txt").write_text("alpha\nneedle here\nbeta\n", encoding="utf-8")
    (root / "sub" / "b.java").write_text(
        "class B {}\nneedle inside java\n", encoding="utf-8")
    (root / "sub" / "c.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "secret.txt").write_text(
        "TOP_SECRET_NEEDLE password=hunter2\n", encoding="utf-8")
    return root


# _jail

def test_jail_accepts_in_root_relative(repo):
    got = lt._jail(repo, "a.txt")
    assert got == (repo / "a.txt").resolve()


def test_jail_accepts_in_root_subdir(repo):
    got = lt._jail(repo, "sub/b.java")
    assert got == (repo / "sub" / "b.java").resolve()


def test_jail_rejects_dotdot_escape(repo):
    # ../secret.txt resolves to the sibling secret -> must be rejected.
    assert lt._jail(repo, "../secret.txt") is None


def test_jail_rejects_deep_dotdot_escape(repo):
    assert lt._jail(repo, "sub/../../secret.txt") is None


def test_jail_rejects_absolute_path_outside_root(repo):
    outside = repo.parent / "secret.txt"
    assert lt._jail(repo, str(outside)) is None


def test_jail_accepts_absolute_path_inside_root(repo):
    inside = repo / "a.txt"
    got = lt._jail(repo, str(inside))
    assert got == inside.resolve()


# _read

def test_read_in_root_returns_numbered_lines(repo):
    out = lt._read(repo, "a.txt")
    assert out.splitlines() == ["1\talpha", "2\tneedle here", "3\tbeta"]


def test_read_out_of_root_blocked(repo):
    out = lt._read(repo, "../secret.txt")
    assert out.startswith("ERROR:")
    assert "outside the repository root" in out
    assert "hunter2" not in out  # secret content never leaks


def test_read_absolute_out_of_root_blocked(repo):
    out = lt._read(repo, str(repo.parent / "secret.txt"))
    assert out.startswith("ERROR:")
    assert "hunter2" not in out


def test_read_missing_file_in_root(repo):
    out = lt._read(repo, "nope.txt")
    assert out.startswith("ERROR: file not found")


def test_read_offset_and_limit(repo):
    out = lt._read(repo, "a.txt", offset=1, limit=1)
    assert out == "2\tneedle here"


def test_read_offset_past_eof(repo):
    out = lt._read(repo, "a.txt", offset=100, limit=10)
    assert out == "(file is empty or offset past EOF)"


# _glob

def test_glob_finds_in_root(repo):
    out = lt._glob(repo, "**/*.java")
    assert out == "sub/b.java"


def test_glob_dotdot_escape_returns_nothing(repo):
    # "../*" must not surface the sibling secret.
    out = lt._glob(repo, "../*")
    assert out == "No files found"
    assert "secret" not in out


def test_glob_no_match(repo):
    assert lt._glob(repo, "**/*.does_not_exist") == "No files found"


def test_glob_strips_leading_slash(repo):
    # Leading slash is stripped, so "/a.txt" still resolves inside root.
    assert lt._glob(repo, "/a.txt") == "a.txt"


# _grep

def test_grep_scan_root_finds_matches(repo):
    out = lt._grep(repo, "needle")
    lines = out.splitlines()
    # Both in-root files with "needle" appear; secret never does.
    assert "a.txt:2:needle here" in lines
    assert "sub/b.java:2:needle inside java" in lines
    assert all("secret" not in ln.lower() for ln in lines)
    assert "hunter2" not in out


def test_grep_never_reads_out_of_root_via_path(repo):
    out = lt._grep(repo, "NEEDLE", path="../secret.txt")
    assert out.startswith("ERROR:")
    assert "outside the repository root" in out
    assert "hunter2" not in out


def test_grep_glob_escape_finds_nothing(repo):
    out = lt._grep(repo, "NEEDLE", glob="../*")
    assert out == "No matches found"
    assert "hunter2" not in out


def test_grep_ignore_case(repo):
    out = lt._grep(repo, "NEEDLE", ignore_case=True)
    assert "a.txt:2:needle here" in out.splitlines()


def test_grep_case_sensitive_no_match(repo):
    out = lt._grep(repo, "NEEDLE")
    assert out == "No matches found"


def test_grep_invalid_regex(repo):
    out = lt._grep(repo, "(")
    assert out.startswith("ERROR: invalid regex")


def test_grep_restrict_to_single_file(repo):
    out = lt._grep(repo, "needle", path="a.txt")
    lines = out.splitlines()
    assert lines == ["a.txt:2:needle here"]


# supported() / schemas

def test_supported_bash_is_missing():
    ok, missing = lt.supported(["Read", "Glob", "Grep", "Bash"])
    assert ok == ["Read", "Glob", "Grep"]
    assert missing == ["Bash"]


def test_supported_all_known():
    ok, missing = lt.supported(["Read", "Grep"])
    assert ok == ["Read", "Grep"]
    assert missing == []


def test_anthropic_schemas_for_shape():
    out = lt.anthropic_schemas_for(["Read", "Bash"])
    # Bash is skipped (not in _SCHEMAS).
    assert len(out) == 1
    entry = out[0]
    assert entry["name"] == "Read"
    assert "description" in entry
    assert entry["input_schema"]["type"] == "object"
    assert entry["input_schema"]["required"] == ["path"]
    # Anthropic envelope uses input_schema, never OpenAI's function nesting.
    assert "function" not in entry
    assert "parameters" not in entry


def test_anthropic_schemas_for_all_tools():
    out = lt.anthropic_schemas_for(["Read", "Glob", "Grep"])
    assert [e["name"] for e in out] == ["Read", "Glob", "Grep"]


def test_schemas_for_openai_envelope():
    out = lt.schemas_for(["Glob", "Bash"])
    assert len(out) == 1
    assert out[0]["type"] == "function"
    assert out[0]["function"]["name"] == "Glob"


# execute() dispatch

def test_execute_read_dispatch(repo):
    out = lt.execute("Read", {"path": "a.txt"}, cwd=str(repo))
    assert out.splitlines()[0] == "1\talpha"


def test_execute_glob_dispatch(repo):
    out = lt.execute("Glob", {"pattern": "**/*.java"}, cwd=str(repo))
    assert out == "sub/b.java"


def test_execute_grep_dispatch(repo):
    out = lt.execute("Grep", {"pattern": "needle"}, cwd=str(repo))
    assert "a.txt:2:needle here" in out.splitlines()


def test_execute_unknown_tool(repo):
    out = lt.execute("Bash", {"command": "ls"}, cwd=str(repo))
    assert out == "ERROR: tool 'Bash' is not available on this backend"


def test_execute_blocks_escape_through_dispatch(repo):
    out = lt.execute("Read", {"path": "../secret.txt"}, cwd=str(repo))
    assert out.startswith("ERROR:")
    assert "hunter2" not in out


def test_execute_handles_none_args(repo):
    # args=None -> falls back to {} -> Read with empty path -> not found.
    out = lt.execute("Read", None, cwd=str(repo))
    assert out.startswith("ERROR:")


# Outbound PII scrubbing: file CONTENT returned to the model must be masked so
# a provider/gateway PII guard cannot reject the request (and PII is not
# egressed). Glob returns paths only and is left untouched. Synthetic test SSN.

def test_execute_read_masks_pii_content(repo):
    (repo / "data.txt").write_text("account ssn = 078-05-1120\n", encoding="utf-8")
    out = lt.execute("Read", {"path": "data.txt"}, cwd=str(repo))
    assert "078-05-1120" not in out
    assert "[REDACTED-SSN]" in out
    # line numbering still present (structure preserved)
    assert out.splitlines()[0].startswith("1\t")


def test_execute_grep_masks_pii_in_match(repo):
    (repo / "data.txt").write_text("ssn: 078-05-1120\n", encoding="utf-8")
    out = lt.execute("Grep", {"pattern": "ssn"}, cwd=str(repo))
    assert "078-05-1120" not in out
    assert "data.txt:" in out  # match location still reported


def test_execute_glob_paths_not_scrubbed(repo):
    out = lt.execute("Glob", {"pattern": "**/*.txt"}, cwd=str(repo))
    assert "a.txt" in out
    assert not out.startswith("ERROR:")


def test_execute_read_clean_file_unchanged(repo):
    out = lt.execute("Read", {"path": "a.txt"}, cwd=str(repo))
    assert out.splitlines() == ["1\talpha", "2\tneedle here", "3\tbeta"]


# Binary / data-URI guard: binary content must never reach the packed text as
# mojibake, and a base64 data-URI must be neutralised (visibly) rather than
# shipped verbatim — a gateway was observed sniffing prompt text for the
# `data:<type>;base64,` marker and rejecting whole requests even when the
# payload was an empty template placeholder, so the marker itself must not
# survive, for ANY payload, while the media type stays legible to a reader.

def test_sanitize_packed_text_passes_clean_text_through():
    assert lt.sanitize_packed_text("plain code\nline 2\n") == "plain code\nline 2\n"


def test_sanitize_packed_text_elides_null_byte_binary():
    out = lt.sanitize_packed_text("PK\x03\x04\x00\x00junk", rel="x.whatever")
    assert out == "[binary content elided: x.whatever is not text]"
    assert "\x00" not in out


def test_sanitize_packed_text_elides_replacement_char_binary():
    out = lt.sanitize_packed_text("�" * 100 + "a" * 100, rel="img")
    assert "binary content elided" in out


def test_sanitize_packed_text_neutralises_long_data_uri():
    blob = "QUJD" * 100                      # 400 base64 chars
    out = lt.sanitize_packed_text(f"<img src='data:image/jpeg;base64,{blob}'>")
    assert blob[:80] not in out              # raw payload gone
    assert ";base64," not in out             # sniffable marker gone too
    assert "<img src='[data-uri image/jpeg elided: 400 chars]'>" == out


def test_sanitize_packed_text_neutralises_short_data_uri():
    # Short payloads are as sniffer-visible as long ones — no length floor.
    out = lt.sanitize_packed_text("<img src='data:image/png;base64,QUJD'>")
    assert "data:image" not in out and ";base64," not in out
    assert "<img src='[data-uri image/png elided: 4 chars]'>" == out


def test_sanitize_packed_text_neutralises_observed_trigger():
    # The exact live trigger (ISS-15): a template placeholder with NO payload.
    # The gateway sniffed the bare `data:image/jpeg;base64,` marker in prompt
    # text and 400-rejected the request, so the marker itself must not survive
    # even when there is nothing after it to elide.
    src = "<img src='data:image/jpeg;base64,{{img_str}}'"
    out = lt.sanitize_packed_text(src)
    assert "data:image" not in out and ";base64," not in out
    assert "image/jpeg" in out               # media type legible to a reader
    assert out == "<img src='[data-uri image/jpeg elided]{{img_str}}'"


def test_sanitize_packed_text_preserves_line_count_and_numbers():
    # The regression guard that matters most: neutralisation is in place on
    # the data-URI line; every other line keeps its exact position, or every
    # reported finding line number downstream shifts.
    blob = "QUJD" * 100
    src = ("line one\n"
           f"<img src='data:image/jpeg;base64,{blob}'>\n"
           "<p src='data:image/gif;base64,{{img_str}}'>\n"
           "line four\n")
    out = lt.sanitize_packed_text(src)
    src_lines, out_lines = src.splitlines(), out.splitlines()
    assert len(out_lines) == len(src_lines)
    assert out_lines[0] == "line one"
    assert out_lines[3] == "line four"
    assert ";base64," not in out


def test_sanitize_packed_text_leaves_base64_prose_alone():
    # Over-match guard: mentioning base64 in prose or a variable name is not a
    # data URI; the grep path must not corrupt ordinary source.
    src = ("# values are base64 encoded before upload\n"
           "base64_payload = base64.b64encode(data)\n")
    assert lt.sanitize_packed_text(src) == src


def test_read_binary_file_returns_elision_marker(repo):
    (repo / "blob.bin").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
    out = lt._read(repo, "blob.bin")
    assert "binary content elided" in out
    assert "\x00" not in out and "�" not in out


def test_read_elides_data_uri_payload(repo):
    blob = "QUJD" * 100
    (repo / "page.html").write_text(
        f"<img src='data:image/jpeg;base64,{blob}'>\n", encoding="utf-8")
    out = lt._read(repo, "page.html")
    assert blob[:80] not in out and ";base64," not in out
    assert "[data-uri image/jpeg elided: 400 chars]" in out


def test_grep_skips_binary_file(repo):
    (repo / "blob.bin").write_bytes(b"needle\x00\x01\x02" + b"\x00" * 32)
    out = lt._grep(repo, "needle")
    assert "blob.bin" not in out             # binary file silently skipped
    assert "a.txt:2:needle here" in out.splitlines()  # text matches intact


def test_grep_match_line_elides_data_uri(repo):
    blob = "QUJD" * 100
    (repo / "page.html").write_text(
        f"needle data:image/jpeg;base64,{blob} end\n", encoding="utf-8")
    out = lt._grep(repo, "needle", path="page.html")
    assert blob[:80] not in out and ";base64," not in out
    assert "[data-uri image/jpeg elided: 400 chars]" in out


# Inventory scoping: the root jail alone still exposes .git/, the scanner's
# own output, and profile-excluded directories. Once s1 registers the walked
# inventory (set_scope), Read/Glob/Grep are confined to it; without a
# registration the confinement-critical directory names are refused anyway.

@pytest.fixture
def scoped(repo):
    """Register a scope of just a.txt for `repo`; always deregister."""
    lt.set_scope(repo, ["a.txt"])
    try:
        yield repo
    finally:
        lt._SCOPE.pop(str(repo.resolve()), None)


def test_read_outside_inventory_refused(scoped):
    out = lt._read(scoped, "sub/c.py")       # real file, but not in inventory
    assert out.startswith("ERROR:")
    assert "excluded from the scan scope" in out
    assert "x = 1" not in out


def test_read_inside_inventory_allowed(scoped):
    assert lt._read(scoped, "a.txt").splitlines()[0] == "1\talpha"


def test_scope_refusal_before_existence_oracle(scoped):
    # An excluded-but-missing path gets the scope error, not "file not found".
    out = lt._read(scoped, "sub/nope.py")
    assert "excluded from the scan scope" in out


def test_glob_filters_to_inventory(scoped):
    out = lt._glob(scoped, "**/*")
    assert out == "a.txt"                    # sub/* exists but is out of scope


def test_grep_filters_to_inventory(scoped):
    out = lt._grep(scoped, "needle")
    assert out.splitlines() == ["a.txt:2:needle here"]  # b.java match filtered


def test_grep_explicit_path_outside_inventory_refused(scoped):
    out = lt._grep(scoped, "needle", path="sub/b.java")
    assert out.startswith("ERROR:")
    assert "excluded from the scan scope" in out


def test_grep_scope_refusal_before_existence_oracle(scoped):
    # An excluded path must be refused identically whether or not it exists —
    # otherwise Grep is an existence oracle over excluded paths (the Grep
    # analogue of test_scope_refusal_before_existence_oracle).
    exists = lt._grep(scoped, "needle", path="sub/b.java")   # real file
    missing = lt._grep(scoped, "needle", path="sub/nope.java")
    assert "excluded from the scan scope" in exists
    assert "excluded from the scan scope" in missing
    # Same message modulo the echoed input path.
    assert exists.replace("sub/b.java", "P") == missing.replace("sub/nope.java", "P")


def test_grep_no_existence_oracle_for_sensitive_paths(scoped):
    # Probe the confinement-critical targets: VCS metadata, checkpoint state,
    # the scanner's own output, and an operator-excluded answer-key stand-in.
    (scoped / ".git").mkdir()
    (scoped / ".git" / "config").write_text("[core]\n", encoding="utf-8")
    (scoped / "checkpoints").mkdir()
    (scoped / "checkpoints" / "s1.json").write_text("{}\n", encoding="utf-8")
    (scoped / "security-scan").mkdir()
    (scoped / "security-scan" / "report.md").write_text("findings\n",
                                                        encoding="utf-8")
    (scoped / "answers").mkdir()
    (scoped / "answers" / "key.md").write_text("planted vulns\n",
                                               encoding="utf-8")
    for exists, missing in [
        (".git/config", ".git/nope"),
        ("checkpoints/s1.json", "checkpoints/nope.json"),
        ("security-scan/report.md", "security-scan/nope.md"),
        ("answers/key.md", "answers/nope.md"),
        ("checkpoints", "checkpoints-nope"),          # directory probes too
    ]:
        a = lt._grep(scoped, ".", path=exists)
        b = lt._grep(scoped, ".", path=missing)
        assert "excluded from the scan scope" in a, exists
        assert a.replace(exists, "P") == b.replace(missing, "P")


def test_grep_in_scope_explicit_path_still_matches(scoped):
    assert lt._grep(scoped, "needle", path="a.txt") == "a.txt:2:needle here"


def test_grep_directory_path_still_recurses(scoped):
    # A directory containing inventory files must keep recursing after the
    # scope-before-existence reordering.
    lt.set_scope(scoped, ["a.txt", "sub/b.java"])
    out = lt._grep(scoped, "needle", path="sub")
    assert out.splitlines() == ["sub/b.java:2:needle inside java"]


def test_grep_directory_path_recurses_without_registered_scope(repo):
    out = lt._grep(repo, "needle", path="sub")
    assert out.splitlines() == ["sub/b.java:2:needle inside java"]


def test_glob_no_existence_oracle_for_excluded_paths(scoped):
    # Glob has no explicit-path branch, but assert the property anyway: an
    # excluded pattern answers the same whether or not the file exists.
    assert lt._glob(scoped, "sub/c.py") == "No files found"     # real file
    assert lt._glob(scoped, "sub/nope.py") == "No files found"  # missing


def test_execute_read_outside_inventory_refused(scoped):
    out = lt.execute("Read", {"path": "sub/c.py"}, cwd=str(scoped))
    assert out.startswith("ERROR:")
    assert "excluded from the scan scope" in out


def test_git_config_refused_even_without_registered_scope(repo):
    (repo / ".git").mkdir()
    (repo / ".git" / "config").write_text(
        "[remote \"origin\"]\n\turl = https://user:tok@host/r.git\n",
        encoding="utf-8")
    out = lt._read(repo, ".git/config")
    assert out.startswith("ERROR:")
    assert "excluded from the scan scope" in out
    assert lt._grep(repo, "tok@host") == "No matches found"
    assert ".git" not in lt._glob(repo, "**/*")


def test_scan_output_dir_refused_even_without_registered_scope(repo):
    (repo / "security-scan").mkdir()
    (repo / "security-scan" / "report.md").write_text("prior findings\n",
                                                      encoding="utf-8")
    out = lt._read(repo, "security-scan/report.md")
    assert "excluded from the scan scope" in out
    assert lt._grep(repo, "prior findings") == "No matches found"


def test_grep_clips_pathologically_long_line(tmp_path, monkeypatch):
    # The regex must only see a bounded prefix of each line (ReDoS guard), and
    # the emitted match line is clipped with a marker — a multi-KB minified
    # blob can't blow up the scan or flood the output.
    monkeypatch.setattr(lt, "_MAX_GREP_LINE", 100)
    root = tmp_path / "r"
    root.mkdir()
    (root / "big.txt").write_text("needle" + "A" * 5000 + "\n", encoding="utf-8")
    out = lt._grep(root, "needle")
    assert "big.txt:1:" in out          # match still found
    assert "line clipped" in out        # output was clipped
    assert "A" * 200 not in out         # full 5k line not emitted
