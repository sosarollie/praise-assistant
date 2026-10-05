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

"""``.env.example`` must parse to the values it appears to declare.

``python-dotenv`` strips a trailing ``#`` comment only from a line that HAS a
value. On a blank assignment it does not::

    K=/path/to.pem  # comment   ->  '/path/to.pem'
    K=              # comment   ->  '# comment'

So a variable left blank *with* an aligned trailing comment — the natural way to
write an optional setting in a tidy template — is handed to the product as the
comment text. This shipped, and a live run surfaced it as::

    WARN [deepagents]: client_cert/key '# mTLS, every via:deepagents role
      (combined PEM)' not found — disabling mTLS
    WARN [cli]: ca_cert '.../profiles/# CA bundle for the via:cli `claude`
      subprocess' not found — not setting NODE_EXTRA_CA_CERTS

Both are TLS settings, so an operator following the documented setup path got
their CA pin and mTLS silently declined — visibly warned about, but naming a
comment rather than anything they wrote. The fix is to leave optional variables
COMMENTED OUT rather than blank-assigned, which also avoids the second, quieter
problem: a bare ``K=`` sets the variable to the empty string, so the template
can shadow something the operator meant to inherit.

This test pins the parse result rather than the file's formatting, so the
template stays free to be reorganised as long as it still means what it says.
"""
from __future__ import annotations

import io
from pathlib import Path

from dotenv import dotenv_values

_ENV_EXAMPLE = Path(__file__).resolve().parents[1] / ".env.example"


# The variables the template deliberately ships blank-assigned: the per-route
# "fill this in" primaries an operator copying the template is expected to
# edit before anything runs (credentials and their endpoints). Everything
# else optional must be COMMENTED OUT, never blank-assigned — see
# test_env_example_optional_variables_are_commented_out_not_blank. Any new
# name lands here only by deliberate review, not because a blank line was
# convenient.
#
_DELIBERATE_BLANKS = {
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_SDK_API_KEY",
    "OPENAI_API_KEY",
}


def test_env_example_declares_no_comment_as_a_value():
    """No variable may resolve to comment text (the blank-assignment trap)."""
    # Self-explaining failure when the repo-root dotfile is not visible in
    # this environment, instead of a raw FileNotFoundError traceback.
    assert _ENV_EXAMPLE.is_file(), f"{_ENV_EXAMPLE} not found/readable here"
    parsed = dotenv_values(stream=io.StringIO(
        _ENV_EXAMPLE.read_text(encoding="utf-8")))
    offenders = {
        k: v for k, v in parsed.items()
        if v is not None and v.lstrip().startswith("#")
    }
    assert not offenders, (
        "these .env.example variables parse to their own trailing comment — "
        "comment the whole line out instead of blank-assigning it: "
        + ", ".join(f"{k}={v!r}" for k, v in sorted(offenders.items()))
    )


def test_env_example_optional_variables_are_commented_out_not_blank():
    """Optional variables must be commented out, never blank-assigned.

    The other half of the fix the module docstring describes, previously
    unasserted: a bare ``KEY=`` parses to the EMPTY STRING, and
    ``load_dotenv`` (``vvaharness/cli.py``, ``override=False``) still SETS a
    variable that is absent from the environment — so a template line the
    operator never touched turns "unset" into "set to ''". For a variable
    like ``SSL_CERT_FILE`` that is a real behaviour change: unset means
    "system trust", empty means a configured-but-empty path. Reintroducing a
    blank ``SSL_CERT_FILE=`` with no trailing comment would have kept the
    comment-as-value test above green; this one catches it.
    """
    assert _ENV_EXAMPLE.is_file(), f"{_ENV_EXAMPLE} not found/readable here"
    parsed = dotenv_values(stream=io.StringIO(
        _ENV_EXAMPLE.read_text(encoding="utf-8")))
    blank = {k for k, v in parsed.items() if v is not None and not v.strip()}
    offenders = blank - _DELIBERATE_BLANKS
    assert not offenders, (
        "these .env.example variables are blank-assigned — comment the whole "
        "line out (a bare KEY= sets the empty string and shadows 'unset'), "
        "or add them to _DELIBERATE_BLANKS with review: "
        + ", ".join(sorted(offenders))
    )
    # Keep the allowlist honest: an entry that is no longer blank-assigned in
    # the file is a silent hole another blank line could hide behind later.
    stale = _DELIBERATE_BLANKS - blank
    assert not stale, (
        "no longer blank-assigned in .env.example — remove from "
        "_DELIBERATE_BLANKS: " + ", ".join(sorted(stale))
    )


def test_the_trap_this_test_guards_is_real():
    """Red-proof: without the fix the assertion above must actually fail.

    A tripwire that cannot fail is worse than no tripwire, because it reads as
    coverage. This pins python-dotenv's real behaviour, so if a future version
    starts stripping comments from blank assignments this test fails and the
    guard above can be retired deliberately rather than left as decoration.
    """
    trapped = dotenv_values(stream=io.StringIO("K=      # a trailing comment\n"))
    assert trapped["K"] == "# a trailing comment"
    # ...while the same comment after a real value IS stripped.
    fine = dotenv_values(stream=io.StringIO("K=/tmp/x.pem  # a trailing comment\n"))
    assert fine["K"] == "/tmp/x.pem"
