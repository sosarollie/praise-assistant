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

"""Inbound source redaction in s4 (_redact_source).

Source code is packed verbatim into the s4 deep-dive prompt. A provider /
gateway PII guard rejects requests that contain live PII (e.g. US SSNs), so
the code MUST be scrubbed before it leaves the process. Historically this hook
masked card numbers only; these tests lock in that SSNs, credentials and keys
are masked too, and that line structure is preserved.

All values below are synthetic test data — the canonical public test SSN
078-05-1120 and well-known test PAN 4111-1111-1111-1111. Offline/deterministic.

_redact_source is also the shared choke point where every s4 loader turns
file bytes into prompt text, so the binary/data-URI guard
(backends.llm.tools.sanitize_packed_text) runs there too — a gateway was
observed rejecting whole s4 requests over an embedded data:image URI. The
packing tests below go through _load_files_full, the real packing path.
"""
from vvaharness.pipeline.stages.s4_deepdive import _load_files_full, _redact_source


def test_masks_ssn():
    out = _redact_source("user.ssn = '078-05-1120'  # lookup\n", "u.py")
    assert "078-05-1120" not in out
    assert "[REDACTED-SSN]" in out


def test_masks_pan_and_ssn_together():
    src = "PAN = '4111111111111111'\nSSN = '078-05-1120'\n"
    out = _redact_source(src, "x.py")
    assert "078-05-1120" not in out
    assert "4111111111111111" not in out


def test_masks_credential_assignment():
    out = _redact_source('api_key = "abcdef123456789"\n', "cfg.py")
    assert "abcdef123456789" not in out
    assert "[REDACTED-SECRET]" in out


def test_preserves_line_count():
    # Finding line numbers depend on the line count being unchanged.
    src = "line one\nssn 078-05-1120 here\nline three\n"
    out = _redact_source(src, "x.py")
    assert len(out.splitlines()) == len(src.splitlines())


def test_clean_code_unchanged():
    src = "def add(a, b):\n    return a + b\n"
    assert _redact_source(src, "x.py") == src


def test_invalid_ssn_left_untouched():
    # area 666 is not a valid SSN -> must not be masked (precision).
    src = "ref = '666-05-1120'\n"
    assert _redact_source(src, "x.py") == src


def test_masks_non_standard_prefix_card_like():
    # Gap closure (CWE-201): a 16-digit card-like run with a NON-3/4/5/6 prefix
    # that also fails the IIN/Luhn gates would slip past BOTH masking layers and
    # egress to the LLM provider. The `card` keyword immediately before the run
    # triggers the Layer-1 context gate, keeping the first 4 digits + length so
    # a researcher can still flag it.
    src = "card = '1234567890123456'\n"
    out = _redact_source(src, "x.py")
    assert "1234567890123456" not in out
    assert "1234XXXXXXXXXXXX" in out          # first-4 kept, remaining 12 masked


def test_masks_non_standard_prefix_with_separators():
    # Same gap, with separators + a '9' prefix; the `pan` keyword triggers the
    # context gate and layout is preserved.
    src = "pan = '9999-8888-7777-6666'\n"
    out = _redact_source(src, "x.py")
    assert "9999-8888-7777-6666" not in out
    assert "9999-XXXX-XXXX-XXXX" in out


def test_masks_luhn_valid_odd_prefix_without_keyword():
    # Luhn gate: a real card-shaped value (Mastercard 2-series, prefix '2', NOT
    # 3/4/5/6) with NO card keyword nearby is still masked because it satisfies
    # the Luhn check digit — every issued PAN does, regardless of IIN.
    src = "x = '2223003122003222'\n"          # Luhn-valid MC 2-series test PAN
    out = _redact_source(src, "x.py")
    assert "2223003122003222" not in out
    assert "2223XXXXXXXXXXXX" in out


def test_contextless_non_card_digit_run_left_untouched():
    # Precision (the fix): a 13-19 digit literal that is neither Luhn-valid nor
    # labelled with a card keyword — e.g. a nanosecond epoch timestamp or a
    # Snowflake/DB id — must NOT be masked. A length-only gate mangled these,
    # corrupting the literal the researcher reasons about for no privacy gain.
    src = "timestamp_ns = 1700000000000000000\nsnowflake_id = 1234567890123456789\n"
    assert _redact_source(src, "x.py") == src


def test_standard_pan_render_unchanged():
    # Regression: a standard 4-prefix PAN is masked exactly as before
    # (first 4 kept, rest X). The widened gate is a strict superset — it must
    # not change how already-covered PANs render.
    out = _redact_source("PAN = '4111111111111111'\n", "x.py")
    assert "4111111111111111" not in out
    assert "4111XXXXXXXXXXXX" in out


def test_short_digit_run_left_untouched():
    # Precision: < 13 digits is not card-like and must NOT be masked
    # (e.g. ports, versions, small ids, 12-digit values).
    src = "port = 8080\nid = 123456789012\n"   # 4-digit and 12-digit runs
    assert _redact_source(src, "x.py") == src


# ── Binary / data-URI guard at the packing choke point ──────────────────────

def test_packed_data_uri_payload_elided_markup_retained(tmp_path):
    # The live failure: a lab template's <img src='data:image/jpeg;base64,…'>
    # made a gateway 400 the whole request. The gateway sniffs the MARKER text,
    # not the payload, so the marker must not survive either — eliding only the
    # payload left the request still rejectable. The media type stays legible
    # and the surrounding markup survives so the model still sees the template.
    blob = "QUJD" * 1000
    (tmp_path / "report.html").write_text(
        f"<html>\n<img src='data:image/jpeg;base64,{blob}'>\n</html>\n",
        encoding="utf-8")
    out = _load_files_full(["report.html"], tmp_path)
    assert blob not in out
    assert "data:image/jpeg;base64," not in out
    assert f"[data-uri image/jpeg elided: {len(blob)} chars]" in out
    assert "<img src=" in out and "</html>" in out


def test_packed_null_byte_binary_elided(tmp_path):
    # An extensionless/unlisted binary decoded with errors="replace" must not
    # be packed as mojibake — it becomes a visible marker, never dropped.
    (tmp_path / "blob").write_bytes(b"PK\x03\x04\x00\x00binary junk")
    out = _load_files_full(["blob"], tmp_path)
    assert "\x00" not in out
    assert "[binary content elided" in out
    assert "=== blob ===" in out          # the file itself is still visible


def test_normal_source_packed_byte_identically(tmp_path):
    # The important one: the guard must be a no-op on ordinary source — any
    # perturbation here would corrupt every scan.
    src = "def add(a, b):\n    return a + b\n\nprint(add(1, 2))\n"
    (tmp_path / "app.py").write_text(src, encoding="utf-8")
    expected = "=== app.py ===\n" + "\n".join(
        f"{i+1:5d}| {ln}" for i, ln in enumerate(src.splitlines())) + "\n"
    assert _load_files_full(["app.py"], tmp_path) == expected


def test_data_uri_elision_preserves_line_numbers(tmp_path):
    # Elision happens IN PLACE on the data-URI line; lines after it must keep
    # their numbers or every downstream finding reference shifts.
    blob = "QUJD" * 100
    (tmp_path / "t.html").write_text(
        f"line one\n<img src='data:image/png;base64,{blob}'>\nline three\n",
        encoding="utf-8")
    out = _load_files_full(["t.html"], tmp_path)
    assert "    1| line one" in out
    assert "    3| line three" in out
