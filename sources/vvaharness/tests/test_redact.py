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

"""Unit tests for vvaharness.report.redact.

Offline and deterministic: pure-function string redaction, no network,
no subprocess, no clock. All card numbers below are well-known public
test PANs (e.g. 4111-1111-1111-1111) — not live cardholder data.
"""
import pytest

from vvaharness.report import redact as R
from vvaharness.report.redact import (
    _cc_network,
    _luhn,
    _ssn_valid,
    redact,
    redact_counts,
    redact_tree,
)

# Low-level validators

def test_luhn_accepts_valid_check_digit():
    assert _luhn("4111111111111111") is True
    assert _luhn("378282246310005") is True


def test_luhn_rejects_bad_check_digit():
    # Flip the last digit of a valid card PAN.
    assert _luhn("4111111111111112") is False
    assert _luhn("1234567890123456") is False


def test_cc_network_gates_by_iin():
    assert _cc_network("4111111111111111") is True       # 16-digit PAN, IIN 4
    assert _cc_network("5555555555554444") is True       # Mastercard 51-55
    assert _cc_network("2223003122003222") is True        # Mastercard 2221-2720
    assert _cc_network("378282246310005") is True         # Amex (15 digits)
    # Leading "9" is not assigned to any network IIN.
    assert _cc_network("9000000000000001") is False


def test_cc_network_length_bounds():
    # Below 12 and above 19 digits are rejected outright.
    assert _cc_network("41111") is False
    assert _cc_network("4" + "1" * 19) is False


def test_ssn_valid_gate():
    assert _ssn_valid("078051120") is True
    # area 000 / 666, group 00, serial 0000 are structurally impossible.
    assert _ssn_valid("000051120") is False
    assert _ssn_valid("666051120") is False
    assert _ssn_valid("078001120") is False
    assert _ssn_valid("078050000") is False
    # area 900-999 is the ITIN range (taxpayer IDs) — sensitive PII, so it is
    # ALLOWED through the gate and masked (content guards flag these too).
    assert _ssn_valid("900051120") is True
    assert _ssn_valid("936184524") is True
    assert _ssn_valid("961080047") is True


def test_itin_9xx_is_masked():
    # 9XX-XX-XXXX (ITIN) must be masked, not just SSA-issued SSN areas.
    out = redact("itin 936-18-4524 and 961-08-0047 on file")
    assert "936-18-4524" not in out
    assert "961-08-0047" not in out
    assert redact.last_counts.get("SSN") == 2


@pytest.mark.parametrize(
    "sep_value",
    [
        "078-05-1120",   # dash (baseline)
        "078 05 1120",   # space
        "078.05.1120",   # dot
        "078\t05\t1120", # tab
    ],
)
def test_ssn_separator_variants_masked(sep_value):
    out = redact(f"value {sep_value} here")
    assert sep_value not in out
    assert "[REDACTED-SSN]" in out
    assert redact.last_counts.get("SSN") == 1


@pytest.mark.parametrize(
    "text",
    [
        "ssn=078051120",
        "SSN: 078051120",
        "social_security_number = 078051120",
        "taxpayer-id 078051120",
        "itin: 936184524",          # bare ITIN
    ],
)
def test_keyworded_bare_ssn_masked(text):
    out = redact(text)
    assert "078051120" not in out and "936184524" not in out
    assert "[REDACTED-SSN]" in out
    assert redact.last_counts.get("SSN") == 1
    # the keyword/prefix is preserved (only the 9-digit value is masked)
    assert out.split("[REDACTED-SSN]")[0].strip() != ""


def test_bare_9_digits_without_keyword_not_masked():
    # Precision boundary: a bare 9-digit number with NO SSN/ITIN keyword is an
    # ordinary id/timestamp — must stay untouched (no blanket \d{9} masking).
    for text in ("trace id 123456789 logged", "order 078051120 shipped",
                 "count = 936184524"):
        out = redact(text)
        assert out == text
        assert "SSN" not in redact.last_counts


# PAN: Luhn + IIN gating

@pytest.mark.parametrize(
    "pan",
    [
        "4111111111111111",       # 16-digit PAN
        "4111 1111 1111 1111",    # space-grouped PAN
        "5555555555554444",       # Mastercard
        "378282246310005",        # Amex
    ],
)
def test_valid_pan_is_masked(pan):
    out = redact(f"the card is {pan} on file")
    assert pan.replace(" ", "") not in out.replace(" ", "")
    assert "[REDACTED-PAN]" in out
    assert redact.last_counts.get("PAN") == 1


@pytest.mark.parametrize("suffix", [".", ".)", ". ", ",", "!",
                                     "/receipt", "-request", "_status", ".json"])
def test_valid_pan_with_punctuation_delimiter_is_masked(suffix):
    pan = "4111111111111111"
    out = redact(f"card {pan}{suffix}")
    assert pan not in out
    assert "[REDACTED-PAN]" in out


@pytest.mark.parametrize("prefix, suffix", [("x", ""), ("", "y"),
                                               ("prefix", "suffix")])
def test_valid_pan_in_alphanumeric_token_is_not_masked(prefix, suffix):
    pan = "4111111111111111"
    text = f"ref {prefix}{pan}{suffix}"
    assert redact(text) == text
    assert "PAN" not in redact.last_counts


def test_random_16_digits_not_masked():
    # Luhn-valid but no real network IIN (leading 9) → left untouched.
    assert _luhn("9000000000000001") is True
    text = "trace id 9000000000000001 here"
    out = redact(text)
    assert out == text
    assert "PAN" not in redact.last_counts


def test_non_luhn_pan_not_masked():
    text = "card 4111111111111112 invalid"
    out = redact(text)
    assert out == text
    assert "PAN" not in redact.last_counts


# SSN

def test_valid_ssn_is_masked():
    out = redact("SSN 078-05-1120 on record")
    assert "078-05-1120" not in out
    assert "[REDACTED-SSN]" in out
    assert redact.last_counts.get("SSN") == 1


def test_invalid_ssn_area_not_masked():
    text = "ref 666-05-1120 ok"
    out = redact(text)
    assert out == text
    assert "SSN" not in redact.last_counts


# Cloud / SaaS credential patterns

@pytest.mark.parametrize(
    "label,secret",
    [
        ("AWS-KEY", "AKIAIOSFODNN7EXAMPLE"),
        ("AWS-KEY", "ASIA" + "A" * 16),
        ("GITHUB-TOKEN", "ghp_" + "a" * 36),
        ("SLACK-TOKEN", "xoxb-" + "1" * 20),
        ("STRIPE-KEY", "sk_live_" + "a" * 24),
        ("STRIPE-KEY", "rk_test_" + "B" * 30),
        ("GOOGLE-API-KEY", "AIza" + "a" * 35),
        ("TWILIO-KEY", "SK" + "0" * 32),
    ],
)
def test_cloud_credential_masked(label, secret):
    out = redact(f"key = {secret} end")
    assert secret not in out
    assert f"[REDACTED-{label}]" in out
    assert redact.last_counts.get(label) == 1


def test_azure_sas_signature_masked():
    out = redact("blob?sig=ABCDabcd1234efgh5678XYZ%2Fpq end")
    assert "[REDACTED-AZURE-SAS]" in out
    assert redact.last_counts.get("AZURE-SAS") == 1


def test_short_aws_lookalike_not_masked():
    # Too few trailing chars to satisfy the AKIA + 16 pattern.
    text = "AKIASHORT end"
    out = redact(text)
    assert out == text
    assert "AWS-KEY" not in redact.last_counts


# JWT / Bearer / Basic / private key

def test_jwt_masked():
    jwt = "eyJ" + "abcdefghij" + "." + "klmnopqrst" + "." + "uvwxyz0123"
    out = redact(f"Authorization: {jwt}")
    assert jwt not in out
    assert "[REDACTED-JWT]" in out
    assert redact.last_counts.get("JWT") == 1


def test_private_key_block_masked():
    pk = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "ABCDEFGHIJKLMNOP\nQRSTUVWXYZ012345\n"
        "-----END RSA PRIVATE KEY-----"
    )
    out = redact(f"embedded:\n{pk}\ntail")
    assert "ABCDEFGHIJKLMNOP" not in out
    assert "[REDACTED-PRIVATE-KEY]" in out
    assert redact.last_counts.get("PRIVATE-KEY") == 1


# SECRET value-shape gate

@pytest.mark.parametrize(
    "text",
    [
        'password: "supersecret"',        # quoted
        "password: hunter2",              # carries a digit
        "secret: abcDEFghi",              # mixed case
        "api_key: aaa-bbb!cc",            # symbol
        "token: " + "a" * 30,             # long opaque token (>=20)
    ],
)
def test_secret_credential_shape_redacted(text):
    out = redact(text)
    assert "[REDACTED-SECRET]" in out
    assert redact.last_counts.get("SECRET") == 1


@pytest.mark.parametrize(
    "text",
    [
        "secret: rotate",        # prose-ambiguous keyword + short lowercase word
        "token: refresh",
        "credential: review",
    ],
)
def test_secret_weak_keyword_plain_word_not_redacted(text):
    out = redact(text)
    assert out == text
    assert "SECRET" not in redact.last_counts


@pytest.mark.parametrize(
    "text",
    [
        "password: correcthorse",       # strong keyword -> value always masked
        "pwd: hunterpw",
        "api_key: supersecret",
        "access_key: accesskeyval",
        "client_secret: clientsecretval",
        "auth_token: authtokenval",
    ],
)
def test_secret_strong_keyword_lowercase_value_redacted(text):
    # An unquoted all-lowercase value after a strong credential keyword is
    # almost always a real secret; the prose carve-out must NOT apply.
    out = redact(text)
    assert "[REDACTED-SECRET]" in out
    assert redact.last_counts.get("SECRET") == 1


@pytest.mark.parametrize(
    "text",
    [
        "password: changeme",
        "password: ${DB_PASS}",
        "secret: <your-secret>",
        "api_key: example",
    ],
)
def test_secret_placeholder_allowlist_not_redacted(text):
    out = redact(text)
    assert out == text
    assert "SECRET" not in redact.last_counts


def test_secret_keeps_keyword_and_quotes_around_mask():
    out = redact('password: "supersecret"')
    # The keyword and the surrounding quotes survive; only the value is masked.
    assert out.startswith("password: ")
    assert out.count('"') == 2
    assert "[REDACTED-SECRET]" in out


def test_secret_backtick_placeholder_not_redacted():
    text = "use `token: ${DB_PASS}` in env"
    out = redact(text)
    assert out == text
    assert "SECRET" not in redact.last_counts


def test_secret_backtick_value_masked_keeps_span_balanced():
    out = redact("password: `hunter2pw`")
    assert "[REDACTED-SECRET]" in out
    assert "hunter2pw" not in out
    assert out.count("`") == 2

@pytest.mark.parametrize(
    "text",
    [
        "superSecret: hunter2pw",
        "myApiKey: abc123def456",
        "dbPassword: s3cr3tvalue",
    ],
)
def test_secret_camelcase_strong_keyword_redacted(text):
    out = redact(text)
    assert "[REDACTED-SECRET]" in out
    assert redact.last_counts.get("SECRET") == 1

@pytest.mark.parametrize(
    "text",
    [
        "secret = (sasl_secret_t *)realloc(p, n);",   # C cast
        "token = parse(input)",                        # function call
        "this.secret = obj.field",                     # member access
    ],
)
def test_secret_code_expression_not_redacted(text):
    out = redact(text)
    assert out == text
    assert "SECRET" not in redact.last_counts


@pytest.mark.parametrize(
    "text",
    [
        "HTTP Basic Authentication is supported",
        "uses Bearer authentication for the API",
        "Basic Authorization header",
    ],
)
def test_bearer_prose_not_redacted(text):
    out = redact(text)
    assert out == text
    assert "BEARER" not in redact.last_counts


# NUL handling, counts, empty input

def test_nul_bytes_stripped_no_indexerror():
    # A literal "\x00<digits>\x00" must not collide with the reinsertion pass.
    out = redact("\x000\x00 hello \x0042\x00 world")
    assert "\x00" not in out
    assert out == "0 hello 42 world"


def test_empty_and_none_passthrough():
    assert redact("") == ""
    assert redact(None) is None


def test_last_counts_aggregates_multiple_hits():
    out = redact("4111111111111111 and 5555555555554444 here")
    assert out.count("[REDACTED-PAN]") == 2
    assert redact.last_counts.get("PAN") == 2


def test_last_counts_reset_between_calls():
    redact("4111111111111111")
    assert redact.last_counts.get("PAN") == 1
    redact("no secrets here at all")
    assert redact.last_counts == {}


def test_clean_text_unchanged():
    text = "This is an ordinary sentence with no secrets."
    out = redact(text)
    assert out == text
    assert redact.last_counts == {}


# redact_tree recursion

def test_redact_tree_recurses_strings_only():
    tree = {
        "card": "PAN 4111111111111111 here",
        "nested": {"list": ["clean", "ghp_" + "a" * 36]},
        "number": 42,
        "flag": True,
        "none": None,
    }
    out = redact_tree(tree)
    assert "4111111111111111" not in out["card"]
    assert "[REDACTED-PAN]" in out["card"]
    assert out["nested"]["list"][0] == "clean"
    assert "[REDACTED-GITHUB-TOKEN]" in out["nested"]["list"][1]
    # Non-string leaves are passed through untouched.
    assert out["number"] == 42
    assert out["flag"] is True
    assert out["none"] is None


def test_redact_tree_preserves_structure():
    out = redact_tree(["a", ["b", {"c": "d"}], 1])
    assert out == ["a", ["b", {"c": "d"}], 1]


def test_secret_does_not_swallow_trailing_period():
    out = redact("token=mysecretvalue9.")
    assert out == "token=[REDACTED-SECRET]."
    assert "mysecretvalue9" not in out


def test_secret_does_not_swallow_trailing_paren_or_sentence():
    out = redact("api_key=abcdef123456) in the call.")
    assert out == "api_key=[REDACTED-SECRET]) in the call."
    assert "abcdef123456" not in out


def test_secret_does_not_swallow_trailing_bracket():
    out = redact("auth_token=abcdefghij]")
    assert out == "auth_token=[REDACTED-SECRET]]"
    assert "abcdefghij" not in out


def test_secret_in_json_object_is_redacted():
    out = redact('config {"token": "abc123def456"}')
    assert "abc123def456" not in out
    assert out.endswith('}')
    assert "[REDACTED-SECRET]" in out


def test_quoted_secret_with_interior_paren_preserved():
    out = redact("password = 'p)ss)word12'")
    assert "p)ss)word12" not in out


def test_prose_carveout_after_weak_keyword_survives():
    assert redact("the secret: management approach") == \
        "the secret: management approach"


def test_strong_keyword_value_always_masked():
    out = redact("password: correcthorse")
    assert "correcthorse" not in out
    assert "[REDACTED-SECRET]" in out


# redact_counts: thread-safe variant used for OUTBOUND (prompt / tool) scrubbing

def test_redact_counts_returns_text_and_counts():
    text, counts = redact_counts("SSN 078-05-1120 and card 4111111111111111")
    assert "078-05-1120" not in text and "[REDACTED-SSN]" in text
    assert "4111111111111111" not in text and "[REDACTED-PAN]" in text
    assert counts.get("SSN") == 1
    assert counts.get("PAN") == 1


def test_redact_counts_output_matches_redact():
    s = "x 078-05-1120 y ghp_" + "a" * 36 + " z"
    assert redact_counts(s)[0] == redact(s)


def test_redact_counts_does_not_touch_global_last_counts():
    # Prime the shared side-channel, then ensure the thread-safe variant
    # leaves it untouched (so concurrent callers can't corrupt each other).
    redact("078-05-1120")
    before = dict(redact.last_counts)
    redact_counts("4111111111111111 and 5555555555554444")  # two PANs
    assert redact.last_counts == before


def test_redact_counts_empty_and_none():
    assert redact_counts("") == ("", {})
    assert redact_counts(None) == (None, {})


def test_redact_counts_clean_text_zero_counts():
    text, counts = redact_counts("ordinary code: return x + 1")
    assert text == "ordinary code: return x + 1"
    assert counts == {}

def test_redact_is_idempotent_no_double_bracket():
    # Re-redacting already-redacted text must be a no-op (a second pass used to
    # append a stray bracket: `token=[REDACTED-SECRET]]`).
    once = redact("token=supersecretvalue123")
    assert once == "token=[REDACTED-SECRET]"
    assert redact(once) == once
    assert "]]" not in redact(once)


def test_url_userinfo_password_masked_user_preserved():
    out = redact("clone https://x-access-token:ghp_SECRETVALUE123@example.com/o/r.git")
    assert "ghp_SECRETVALUE123" not in out
    assert "x-access-token" in out                 # username/scheme preserved
    assert "[REDACTED-URL-CRED]" in out
    # a host:port URL with no credentials must NOT match
    assert redact("see https://api.example.com:443/v1") \
        == "see https://api.example.com:443/v1"


def test_large_private_key_block_masked():
    # A key body larger than the old 16 KB cap must still be masked (the cap
    # used to fail open and leak the whole block).
    big = ("-----BEGIN RSA PRIVATE KEY-----\n"
           + "A" * 20000 + "\n-----END RSA PRIVATE KEY-----")
    out = redact("key: " + big)
    assert "[REDACTED-PRIVATE-KEY]" in out
    assert "A" * 100 not in out


def test_ssn_unicode_space_separators_masked():
    # NBSP / narrow-no-break separated SSN must mask; a value split across
    # newlines must NOT (avoids matching numbers across table rows).
    assert "[REDACTED-SSN]" in redact("id 078\u00a005\u00a01120 x")
    assert "[REDACTED-SSN]" in redact("id 078\u202f05\u202f1120 x")
    assert "[REDACTED-SSN]" not in redact("078\n05\n1120")


def test_redact_tree_traverses_tuples():
    """A secret inside a tuple must not survive redaction.

    Tuples used to fall through to the passthrough branch, so a string leaf in one was
    returned verbatim. That is reachable now that the contract models in vvaharness.models
    use tuples throughout: only ``model_dump(mode="json")`` -- which happens to convert them
    to lists -- stood between a tuple-carrying payload and a secret on disk.
    """
    from vvaharness.report.redact import redact_tree

    secret = 'password="hunter2seekrit"'
    assert "hunter2seekrit" not in redact_tree((secret,))[0]
    # Nested, and the container type is preserved rather than coerced to a list.
    out = redact_tree({"a": ({"b": [secret]},)})
    assert isinstance(out["a"], tuple)
    assert "hunter2seekrit" not in out["a"][0]["b"][0]


def test_upper_snake_env_var_names_are_recognised():
    """`api_key=` matched but `ANTHROPIC_API_KEY=` did not — the spelling logs actually contain.

    `_` is a word character, so there is no \\b before API, and the camelCase lookbehind only
    accepted a lowercase letter."""
    for line in ("ANTHROPIC_API_KEY=sk-ant-api03-REALKEY0000000000",
                 "MY_AUTH_TOKEN=hunter2trustme",
                 "DB_PASSWORD=hunter2trustme"):
        out = redact(line)
        assert "REALKEY" not in out and "hunter2trustme" not in out, out
        assert "REDACTED" in out


def test_anthropic_key_shape_is_masked_without_a_key_prefix():
    """The credential this product authenticates with had no pattern of its own.

    Stripe and Google key shapes were covered; a bare `sk-ant-…` with nothing to anchor the
    assignment pattern on survived verbatim."""
    assert "REALKEY" not in redact("sk-ant-api03-REALKEY0000000000")
    assert redact("sk-ant-api03-REALKEY0000000000") == "[REDACTED-ANTHROPIC-KEY]"


def test_ordinary_prose_about_api_design_is_untouched():
    """The anchor widening must not turn every mention of an api into a redaction."""
    text = "just a normal sentence about api design and token economics"
    assert redact(text) == text


def test_log_records_are_redacted_before_they_reach_a_handler():
    """Diagnostic logging must not become a new credential egress.

    31 modules log and nothing configured a handler, so enabling it is new egress: a log line
    quotes config values, file contents and exception text."""
    import io
    import logging

    from vvaharness.util.logs import configure

    logging.getLogger("vvaharness").handlers.clear()
    assert configure("info") is True
    buf = io.StringIO()
    logging.getLogger("vvaharness").handlers[0].stream = buf
    logging.getLogger("vvaharness.t").warning(
        "loaded ANTHROPIC_API_KEY=sk-ant-api03-REALKEY0000000000 for %s", "AKIAIOSFODNN7EXAMPLE")
    out = buf.getvalue()
    # Restore the import-time logger state BEFORE asserting: configure() sets
    # propagate=False (logs.py, deliberate in production), and leaking that
    # would silence caplog for every later test file in the session -- which is
    # exactly how tests/test_validate_collect.py's caplog assertions broke.
    # Mirrors _reset_channel() in tests/test_cli_logging.py.
    _pkg = logging.getLogger("vvaharness")
    _pkg.handlers.clear()
    _pkg.setLevel(logging.NOTSET)
    _pkg.propagate = True
    assert "REALKEY" not in out and "AKIAIOSFODNN7EXAMPLE" not in out, out
    assert "REDACTED" in out


def test_logging_is_off_unless_asked_for():
    """Default silence is the point: the curated stderr interleaves with an in-place spinner."""
    import logging
    import os

    from vvaharness.util.logs import configure

    for var in ("VVAHARNESS_LOG_LEVEL", "VVAHARNESS_LOG_FILE"):
        os.environ.pop(var, None)
    logging.getLogger("vvaharness").handlers.clear()
    assert configure() is False
    assert configure("shout") is False       # a bad level degrades, never raises
