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

"""Pull a JSON object/array out of a model response that may have prose around it."""
from __future__ import annotations

import json
import re
import sys

# Strip ```json ... ``` fences if present, then find the first balanced
# brace/bracket block. Good enough for structured-output prompts.
_FENCE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)
# Leading fence opener only (```/```json/```python …) — used to peek past it
# at the first content character without committing to a closing fence.
_FENCE_OPEN = re.compile(r"^```\w*\s*")

# Defensive ceiling on the text scanned. The balanced-span scan is O(openers ×
# length), so a pathological blob with many '{'/'[' could be quadratic. Normal
# LLM envelopes are a few KB; this cap (~5 MB) only ever trims a runaway
# response, and we scan the bounded window rather than abandoning the parse.
_MAX_JSON_INPUT = 5_000_000

_VALID_ESCAPE = set('"\\/nrtu')


def _repair_invalid_escapes(s: str) -> str:
    """Best-effort repair: double any backslash that does NOT introduce a valid
    JSON escape, so a value like ``"\\d+"`` (regex) or ``"C:\\Users"`` (path)
    parses. Backslashes only legally appear inside JSON string literals, so
    scanning the whole span is safe; genuinely valid escapes (``\\\\`` ``\\"``
    ``\\n`` ``\\uXXXX`` …) are left untouched."""
    out: list[str] = []
    i, n = 0, len(s)
    while i < n:
        ch = s[i]
        if ch == "\\":
            nxt = s[i + 1] if i + 1 < n else ""
            if nxt in _VALID_ESCAPE:
                out.append(ch)
                out.append(nxt)
                i += 2
                continue
            out.append("\\\\")   # invalid / trailing escape -> literal backslash
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _balanced_span(s: str, start: int) -> str | None:
    open_ch = s[start]
    close_ch = "}" if open_ch == "{" else "]"
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(s)):
        ch = s[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch == open_ch:
                depth += 1
            elif ch == close_ch:
                depth -= 1
                if depth == 0:
                    return s[start:i + 1]
    return None


def extract_json(text: str) -> dict | list:
    if len(text) > _MAX_JSON_INPUT:
        print(f"  [json_extract] WARN: input {len(text)} bytes exceeds "
              f"{_MAX_JSON_INPUT}; scanning the first {_MAX_JSON_INPUT} only",
              file=sys.stderr)
        text = text[:_MAX_JSON_INPUT]
    stripped = text.strip()
    # Prefer fenced block(s), but ALWAYS keep the whole response as a final
    # candidate so JSON placed OUTSIDE a (possibly non-JSON) fenced block — e.g.
    # an agent that shows a code snippet in a fence then trails the real JSON —
    # is still recovered instead of dropped.
    candidates: list[str] = []
    # A literal ``` appearing INSIDE a JSON string value (e.g. a chain
    # narrative quoting a code block) makes the non-greedy _FENCE.findall()
    # terminate at that inner ``` and return a truncated, unbalanced body. When
    # the WHOLE trimmed response is one fenced block, an anchored fullmatch
    # yields the correct full body regardless of inner backticks — try that
    # first. This is purely additive: the original findall() candidates remain
    # below, so every input the old code handled still falls through unchanged.
    whole = _FENCE.fullmatch(stripped)
    if whole:
        candidates.append(whole.group(1))
    candidates += _FENCE.findall(text)
    candidates.append(text)

    # Defence-in-depth for the same failure: if the response (past any opening fence)
    # visibly starts with '{', a top-level *list* result is almost certainly a
    # sub-span like "[10]" that happened to balance inside a string literal.
    # Hold the first such list and keep scanning for a dict; only return the
    # held list if no dict is found in any candidate. When the response does
    # NOT start with '{' this guard is inert and behaviour is unchanged.
    peek = _FENCE_OPEN.sub("", stripped, count=1)
    want_dict = peek[:1] == "{"
    held_list: list | None = None
    last_err: Exception | None = None

    for cand in candidates:
        i = 0
        while i < len(cand):
            if cand[i] not in "{[":
                i += 1
                continue
            span = _balanced_span(cand, i)
            if span is None:
                # Unbalanced/garbage opener (e.g. a stray "{" in prose or a
                # truncated fence). Don't abandon the candidate — advance past
                # this opener and keep scanning for a later balanced block.
                i += 1
                continue
            val = None
            try:
                val = json.loads(span)
            except json.JSONDecodeError as e:
                last_err = e
                # LLMs frequently emit invalid backslash escapes inside string
                # values (regexes \d, Windows paths C:\…, code).
                repaired = _repair_invalid_escapes(span)
                if repaired != span:
                    try:
                        val = json.loads(repaired)
                    except json.JSONDecodeError:
                        pass
            if val is None:
                i += len(span)
                continue
            if want_dict and isinstance(val, list):
                if held_list is None:
                    held_list = val
                i += len(span)
                continue
            return val

    if held_list is not None:
        return held_list
    if last_err:
        raise last_err
    raise ValueError("no JSON object found in response")
