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

"""Unit tests for vvaharness.util.json_extract.extract_json."""
import json

import pytest

from vvaharness.util.json_extract import extract_json


def test_plain_json_object():
    assert extract_json('{"a": 1, "b": "x"}') == {"a": 1, "b": "x"}


def test_plain_json_array():
    assert extract_json("[1, 2, 3]") == [1, 2, 3]


def test_fenced_json_block():
    text = 'Here is the result:\n```json\n{"k": "v"}\n```\nThanks!'
    assert extract_json(text) == {"k": "v"}


def test_fenced_block_without_json_tag():
    text = "```\n[true, false, null]\n```"
    assert extract_json(text) == [True, False, None]


def test_prose_surrounding_plain_json():
    text = 'The answer is {"ok": true} for sure.'
    assert extract_json(text) == {"ok": True}


def test_json_outside_fence_recovered_as_fallback():
    # A non-JSON code snippet is fenced; the REAL JSON trails outside the fence.
    # The fenced candidate fails to parse, but the whole-text fallback recovers it.
    text = (
        "Here is some code:\n"
        "```python\n"
        "def f(x):\n"
        "    return x + 1\n"
        "```\n"
        'Result: {"verdict": "confirmed", "score": 9}'
    )
    assert extract_json(text) == {"verdict": "confirmed", "score": 9}


def test_nested_json_object():
    obj = {"outer": {"inner": [1, {"deep": "value"}]}, "n": 2}
    assert extract_json("noise " + json.dumps(obj) + " more noise") == obj


def test_string_with_braces_does_not_break_balance():
    # Braces inside a JSON string must not be counted toward brace depth.
    text = '{"template": "use {placeholder} here", "done": true}'
    assert extract_json(text) == {"template": "use {placeholder} here", "done": True}


def test_escaped_quote_inside_string():
    text = r'{"msg": "she said \"hi\"", "ok": true}'
    assert extract_json(text) == {"msg": 'she said "hi"', "ok": True}


def test_stray_open_brace_in_prose_then_valid_json():
    # A lone "{" with no closer should be skipped; scanning continues to the
    # later balanced, valid block.
    text = 'broken { not json here. but later: {"real": 42}'
    assert extract_json(text) == {"real": 42}


def test_first_balanced_block_returned_when_multiple():
    text = '{"first": 1} and then {"second": 2}'
    assert extract_json(text) == {"first": 1}


def test_malformed_balanced_block_raises_json_error():
    # A balanced block that is not valid JSON (trailing comma) and no other
    # parseable candidate -> the JSONDecodeError is re-raised.
    with pytest.raises(json.JSONDecodeError):
        extract_json('{"a": 1,}')


def test_no_json_raises_value_error():
    with pytest.raises(ValueError) as exc:
        extract_json("just some prose with no structured data")
    assert "no JSON object found" in str(exc.value)


def test_empty_string_raises_value_error():
    with pytest.raises(ValueError):
        extract_json("")


def test_unbalanced_only_raises_value_error():
    # Openers exist but never balance -> no candidate parses, no JSONDecodeError
    # was recorded because no balanced span was found -> ValueError.
    with pytest.raises(ValueError) as exc:
        extract_json("prefix { unclosed [ also unclosed")
    assert "no JSON object found" in str(exc.value)


def test_malformed_then_valid_recovered():
    # First balanced block is invalid JSON; a later balanced block is valid.
    # extract_json advances past the bad span and recovers the good one.
    text = '{bad json} then {"good": "yes"}'
    assert extract_json(text) == {"good": "yes"}


def test_array_with_mixed_types():
    text = '```json\n[1, "two", {"three": 3}, [4]]\n```'
    assert extract_json(text) == [1, "two", {"three": 3}, [4]]


def test_repairs_invalid_regex_escape():
    # `\d` is not a valid JSON escape; the repair doubles it so the value parses.
    out = extract_json(r'{"pattern": "\d+ digits", "n": 1}')
    assert out == {"pattern": r"\d+ digits", "n": 1}


def test_repairs_windows_path_escape():
    out = extract_json(r'{"file": "C:\Users\app\x.txt"}')
    assert out == {"file": r"C:\Users\app\x.txt"}


def test_repairs_invalid_escape_inside_fence():
    out = extract_json('```json\n{"re": "a\\.b\\s+c"}\n```')
    assert out == {"re": r"a\.b\s+c"}


def test_valid_escapes_preserved_not_double_escaped():
    # A genuinely valid \n and an escaped backslash must survive intact.
    out = extract_json(r'{"a": "line\nbreak", "b": "esc\\slash"}')
    assert out == {"a": "line\nbreak", "b": "esc\\slash"}


def test_repair_helper_doubles_only_invalid():
    from vvaharness.util.json_extract import _repair_invalid_escapes
    assert _repair_invalid_escapes(r'"\d"') == r'"\\d"'      # invalid -> doubled
    assert _repair_invalid_escapes(r'"\\"') == r'"\\"'       # valid \\ -> unchanged
    assert _repair_invalid_escapes(r'"\n"') == r'"\n"'       # valid \n -> unchanged
    uni = '"' + '\\u00e9' + '"'                               # the 8 chars "é"
    assert _repair_invalid_escapes(uni) == uni                # valid \u -> unchanged
    assert _repair_invalid_escapes(r'"\b"') == r'"\\b"'      # \b -> literal (domain choice)


def test_repairs_windows_path_with_b_segment():
    # \b is a valid JSON escape (backspace) but a model emitting "C:\bin" means a
    # literal path; the repair treats \b/\f as literal so the path round-trips.
    out = extract_json(r'{"p": "C:\bin\app.exe"}')
    assert out == {"p": r"C:\bin\app.exe"}


def test_inner_backticks_do_not_truncate_fenced_object():
    # The s8 chain narrative quotes a code block (```py x```) INSIDE a JSON
    # string, and the summary contains "[10]"-style finding refs. Pre-fix the
    # non-greedy fence match truncated at the inner ``` and the scanner returned
    # the spurious list [10]; the real outer dict was discarded.
    text = ('```json\n'
            '{"summary":"chain ([10]+[11]+[8]) is critical",'
            '"chains":[{"narrative":"send ```py x``` then pivot"}]}\n'
            '```')
    out = extract_json(text)
    assert isinstance(out, dict)
    assert out["summary"] == "chain ([10]+[11]+[8]) is critical"
    assert out["chains"][0]["narrative"] == "send ```py x``` then pivot"


def test_inner_backticks_with_trailing_prose():
    # Same as above but with prose AFTER the closing fence, so the anchored
    # fullmatch does NOT apply — exercises the defence-in-depth path (a list
    # matched inside a '{'-opening response is held, dict found in full text).
    text = ('```json\n'
            '{"summary":"([10]+[11])","chains":[{"n":"```code``` here"}]}\n'
            '```\n'
            'Let me know if you need more detail.')
    out = extract_json(text)
    assert isinstance(out, dict)
    assert out["chains"][0]["n"] == "```code``` here"


def test_want_dict_guard_inert_when_response_is_array():
    # The want-dict guard must NOT swallow a legitimate top-level array.
    text = '```json\n[{"index": 0}, {"index": 1}]\n```'
    assert extract_json(text) == [{"index": 0}, {"index": 1}]


def test_held_list_returned_when_no_dict_anywhere():
    # Response opens with '{' (so want_dict is on) but the only PARSEABLE span
    # is a list — the held list must still be returned, not lost.
    text = '{unparseable [1, 2, 3] tail'
    assert extract_json(text) == [1, 2, 3]


def test_extract_json_bounds_oversized_input(monkeypatch, capsys):
    # An over-ceiling input is clipped to a bounded window (and warned), but
    # valid JSON within the window is still parsed.
    from vvaharness.util import json_extract as J
    monkeypatch.setattr(J, "_MAX_JSON_INPUT", 50)
    big = '{"ok": 1}' + " " + "x" * 500
    assert J.extract_json(big) == {"ok": 1}
    assert "exceeds" in capsys.readouterr().err
