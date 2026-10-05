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

"""Sensitive-data redaction for emitted reports (MD + SARIF), applied at the write boundary."""
from __future__ import annotations

import re
from typing import Callable, TypeVar

#: Preserves the caller's structure type through redact_tree; see its docstring for why this is a TypeVar rather than PEP 695 syntax.
_TreeT = TypeVar("_TreeT")

# Validators

def _luhn(digits: str) -> bool:
    total, odd = 0, True
    for ch in reversed(digits):
        n = int(ch)
        if not odd:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        odd = not odd
    return total % 10 == 0


def _cc_network(digits: str) -> bool:
    """IIN/BIN gate so random Luhn-passing 16-digit ids aren't masked."""
    n = len(digits)
    if n < 12 or n > 19:
        return False
    p1, p2 = digits[0], int(digits[:2])
    p3 = int(digits[:3]) if n >= 3 else -1
    p4 = int(digits[:4]) if n >= 4 else -1
    if n == 15 and p2 in (34, 37):                       # Amex
        return True
    if p1 == "4" and 13 <= n <= 19:                      # Visa
        return True
    if n == 16 and (51 <= p2 <= 55 or 2221 <= p4 <= 2720):  # Mastercard
        return True
    if 16 <= n <= 19 and (p4 == 6011 or p2 == 65 or 644 <= p3 <= 649):  # Discover
        return True
    if 16 <= n <= 19 and 3528 <= p4 <= 3589:             # JCB
        return True
    if 16 <= n <= 19 and p2 == 62:                       # UnionPay
        return True
    if 14 <= n <= 19 and p2 == 36:                       # Diners
        return True
    if 12 <= n <= 19 and p4 in (5018, 5020, 5038, 5893,
                                6304, 6759, 6761, 6762, 6763):  # Maestro
        return True
    if n == 16 and (p3 == 508 or p2 in (81, 82)):        # RuPay
        return True
    return False


def _ssn_valid(d: str) -> bool:
    a, g, s = int(d[:3]), int(d[3:5]), int(d[5:9])
    # Rejects only structurally-impossible groupings; area 900-999 (ITIN) is intentionally allowed since it's still masked.
    return not (a == 0 or a == 666 or g == 0 or s == 0)


def _bearer_credential(m: re.Match) -> bool:
    """True only when the value has a non-alphabetic char, guarding against prose like ``HTTP Basic Authentication``."""
    return any(not c.isalpha() for c in m.group("bv"))

_SECRET_CODE_SHAPE = re.compile(
    r"^\("                 # leading paren / cast:   (sasl_secret_t
    r"|^[A-Za-z_]\w*\("    # function call:          parse(
    r"|^[A-Za-z_]\w*\.\w"  # member access:          obj.field / this.field
)


# Patterns  (label, compiled-regex, optional validator(match)->bool)

_b64u = r"[A-Za-z0-9_-]"

_PATTERNS: list[tuple[str, re.Pattern, Callable[[re.Match], bool] | None]] = [
    ("PAN",
        re.compile(r"(?<![0-9A-Za-z])"
                # \s also matches Unicode NBSP/thin/figure space, so a PAN split by those isn't bypassed.
                r"(?:\d[\s\-]?){12,18}\d"
                 # Mask PANs in punctuation-delimited paths and identifiers;
                 # only alphanumeric adjacency makes a value non-standalone.
                 r"(?![0-9A-Za-z])"),
     lambda m: (lambda d: _cc_network(d) and _luhn(d))(re.sub(r"\D", "", m.group(0)))),
    ("CVV",
     re.compile(r"(?i)\b(cvv2?|cvc2?|cid|csc)\b\s*[:=]?\s*\"?(\d{3,4})\"?"),
     None),
    ("TRACK",
     re.compile(r"%B\d{12,19}\^[^?]{2,90}\?"),
     None),

    # Separated SSN/ITIN: NNN-NN-NNNN with '-', '.', tab or single space.
    ("SSN",
     # Separator class includes Unicode spaces so a split SSN isn't bypassed; \n/\r excluded to avoid spanning table rows.
     re.compile(r"(?<!\d)(\d{3})[-.\t \u00a0\u2009\u202f\u2007]"
                r"(\d{2})[-.\t \u00a0\u2009\u202f\u2007](\d{4})(?!\d)"),
     lambda m: _ssn_valid(m.group(1) + m.group(2) + m.group(3))),
    # Keyword-gated BARE 9-digit SSN/ITIN, so arbitrary 9-digit ids/timestamps aren't masked.
    ("SSN-CTX",
     re.compile(
         r"(?i)\b(ssn|social[\s_-]*sec(?:urity)?(?:[\s_-]*(?:no|num|number))?"
         r"|itin|tin|taxpayer[\s_-]*id)\b['\"]?\s*[:=#-]?\s*['\"]?"
         r"(?<!\d)(\d{9})(?!\d)"),
     lambda m: _ssn_valid(m.group(2))),

    ("AWS-KEY",
     re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b"),
     None),
    ("GITHUB-TOKEN",
     re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}"
                r"|github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9]{59})\b"),
     None),
    ("SLACK-TOKEN",
     re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,72}\b"),
     None),
    # The credential THIS product uses; bare tokens carry no `key=` prefix for SECRET to anchor on.
    ("ANTHROPIC-KEY",
     re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b"),
     None),
    ("STRIPE-KEY",
     re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,99}\b"),
     None),
    ("GOOGLE-API-KEY",
     re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
     None),
    ("AZURE-SAS",
     re.compile(r"(?i)\bsig=[0-9A-Za-z%+/=]{20,}\b"),
     None),
    ("TWILIO-KEY",
     re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
     None),

    ("JWT",
     re.compile(r"\beyJ" + _b64u + r"{10,}\." + _b64u + r"{10,}\." + _b64u + r"{10,}\b"),
     None),
    ("BEARER",
     re.compile(r"(?i)\b(?:Bearer|Basic)\s+(?P<bv>[A-Za-z0-9+/=._-]{8,})\b"),
     _bearer_credential),

    # Masks ONLY the password component; only fires on real userinfo, so a host:port URL never matches.
    ("URL-CRED",
     re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://[^\s:/@]+:)([^\s/@]{1,256})@"),
     None),

    # Unbounded lazy body is linear-safe; a bounded cap used to FAIL OPEN on large keys (RSA-16384, multi-key bundles).
    ("PRIVATE-KEY",
     re.compile(r"-{5}BEGIN [A-Z ]*PRIVATE KEY-{5}[\s\S]*?-{5}END [A-Z ]*PRIVATE KEY-{5}"),
     None),

    ("SECRET",
     re.compile(
         # Also accepts camelCase (`superSecret`) and UPPER_SNAKE (`ANTHROPIC_API_KEY`) boundaries, not just `\b`-delimited names.
         r"(?i)(?:\b|(?<=[a-z])|(?<=_))(pass(?:word|wd)?|pwd|secret|api[_-]?key|access[_-]?key"
         r"|client[_-]?secret|auth[_-]?token|token|credential)s?\b"
         r"['\"`]?\s*[:=]\s*"           # tolerate a JSON/markdown closing delimiter: "token": / `token`:
         # \x00 excluded so SECRET never re-captures a placeholder sentinel left by an earlier pattern.
         r"(?P<q>['\"`]?)(?P<v>[^\s'\"`,;\x00]{6,256})(?P=q)"),
     lambda m: not re.fullmatch(
         # Matching a `[REDACTED-...]` placeholder makes redact() idempotent instead of double-bracketing on a second pass.
         r"(?i)\$\{?[A-Z0-9_.]+}?|%[A-Z0-9_]+%|<[^>]+>|\*{3,}|x{3,}"
         r"|\[?redacted]?|\[redacted-[a-z0-9-]+]"
         r"|null|none|true|false|changeme|your[_-]?\w+|placeholder|example",
         m.group("v"))),
]


# Public API

def _redact_impl(text: str) -> tuple[str, dict[str, int]]:
    """Core masking pass. Returns (masked_text, counts); pure / no globals, so safe for concurrent threads."""
    # Strip any pre-existing NUL bytes, since NUL is reserved as the in-band placeholder sentinel below.
    if "\x00" in text:
        text = text.replace("\x00", "")
    counts: dict[str, int] = {}
    placeholders: list[str] = []
    sentinel = "\x00{}\x00"

    def _mask(label: str, m: re.Match) -> str:
        counts[label] = counts.get(label, 0) + 1
        placeholders.append(f"[REDACTED-{label}]")
        return sentinel.format(len(placeholders) - 1)

    out = text
    for label, rx, validator in _PATTERNS:
        def _sub(m: re.Match, _label=label, _ok=validator) -> str:
            if _ok is not None and not _ok(m):
                return m.group(0)
            if _label == "SECRET":
                v = m.group("v")
                quoted = bool(m.group("q"))
                v_core = v if quoted else (v.rstrip(").}]!?>") or v)
                if len(v_core) < 6:
                    v_core = v
                keyword = re.sub(r"[^a-z]", "", m.group(1).lower())
                strong = {"password", "passwd", "pwd", "apikey",
                          "accesskey", "clientsecret", "authtoken"}
                generic_unquoted = keyword not in strong and not quoted
                # Don't mask prose (`secret: management`) or code-expression RHS after a *generic* keyword; strong keywords always mask.
                plain_word = (generic_unquoted
                              and v_core.isalpha() and v_core.islower()
                              and len(v_core) < 20)
                code_shape = generic_unquoted and bool(_SECRET_CODE_SHAPE.match(v_core))
                if plain_word or code_shape:
                    return m.group(0)
                head = m.group(0)[: m.start("v") - m.start(0)]
                tail = v[len(v_core):] + m.group(0)[m.end("v") - m.start(0):]
                return head + _mask(_label, m) + tail
            if _label == "CVV":
                return m.group(0)[: m.start(2) - m.start(0)] + _mask(_label, m)
            if _label == "SSN-CTX":
                # Mask only the 9-digit value, emitting the canonical "SSN" label so counts match the separated-SSN rule.
                return m.group(0)[: m.start(2) - m.start(0)] + _mask("SSN", m)
            if _label == "URL-CRED":
                # Keep "scheme://user:" (group 1), mask the password (group 2), restore the trailing "@".
                return m.group(1) + _mask(_label, m) + "@"
            return _mask(_label, m)
        out = rx.sub(_sub, out)

    if placeholders:
        def _reinsert(m: re.Match) -> str:
            idx = int(m.group(1))
            # Defensive: an out-of-range index can only come from a sentinel collision; leave it untouched rather than raise.
            return placeholders[idx] if 0 <= idx < len(placeholders) else m.group(0)
        out = re.sub(r"\x00(\d+)\x00", _reinsert, out)
    return out, counts


def redact(text: str) -> str:
    """Return `text` with card data, PII and credential material masked; use `redact_counts()` under concurrency instead."""
    if not text:
        return text
    out, counts = _redact_impl(text)
    redact.last_counts = dict(counts)  # type: ignore[attr-defined]
    return out


def redact_counts(text: str) -> tuple[str, dict[str, int]]:
    """Thread-safe variant of `redact()`: returns (masked_text, counts), never touching the shared `redact.last_counts`."""
    if not text:
        return text, {}
    return _redact_impl(text)


def redact_tree(obj: _TreeT) -> _TreeT:
    """Recursively redact every string leaf (dicts, lists, tuples) in a JSON-serialisable structure, before json.dumps."""
    if isinstance(obj, dict):
        return {k: redact_tree(v) for k, v in obj.items()}  # type: ignore[return-value]
    if isinstance(obj, list):
        return [redact_tree(v) for v in obj]  # type: ignore[return-value]
    if isinstance(obj, tuple):
        return tuple(redact_tree(v) for v in obj)  # type: ignore[return-value]
    if isinstance(obj, str):
        return redact(obj)  # type: ignore[return-value]
    return obj
