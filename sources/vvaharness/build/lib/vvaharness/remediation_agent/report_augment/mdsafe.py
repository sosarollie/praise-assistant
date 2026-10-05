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

"""remediation_agent.report_augment.mdsafe — escape untrusted text for Markdown.

Remediation summaries / reasons / file names originate from the LLM/plugin and
are interpolated into the combined Markdown report. :func:`_md_escape` and
:func:`_md_code_span` neutralise inline Markdown/HTML metacharacters and strip
control chars so a field cannot forge report structure or inject active content
(CWE-79)."""
from __future__ import annotations

# Shared render-boundary regexes: _MD_LINEBREAK_RX folds every separator
# str.splitlines() honours (CR/LF, VT, FF, FS/GS/RS, NEL, U+2028/U+2029) to a
# space; _MD_INVISIBLE_RX strips the remaining C0 controls plus zero-width and
# bidirectional format characters (Trojan-Source style). Imported rather than
# duplicated, matching validation/report/augment.py. No cycle:
# vvaharness.models imports nothing from vvaharness.remediation_agent.
from vvaharness.models import _MD_INVISIBLE_RX, _MD_LINEBREAK_RX

# Inline Markdown / HTML metacharacters that could forge emphasis/links/code
# spans, inject HTML (active content in a permissive renderer), or break out of
# a table cell. Newlines are collapsed to spaces first, so line-start constructs
# (headings, list bullets) cannot be forged and need no escaping here.
_MD_ESCAPE = {
    "\\": "\\\\", "`": "\\`", "*": "\\*", "_": "\\_",
    "[": "\\[", "]": "\\]", "|": "\\|", "#": "\\#",
    "<": "&lt;", ">": "&gt;", "&": "&amp;",
}


def _md_escape(value: object) -> str:
    """Escape untrusted (model/DTO-controlled) text for safe inline Markdown.

    Remediation summaries and reasons originate from the LLM/plugin and are
    interpolated into the combined Markdown report. Without escaping they can
    forge report structure, hide content, or — in an HTML-capable Markdown
    renderer — inject active content (CWE-79). This neutralises inline
    Markdown/HTML metacharacters, strips invisible control/format characters,
    and collapses line breaks (including the Unicode separators
    ``splitlines()`` honours) to spaces so a single field cannot break out of
    its line/bullet."""
    text = _MD_LINEBREAK_RX.sub(" ", str(value))
    text = _MD_INVISIBLE_RX.sub("", text)
    return "".join(_MD_ESCAPE.get(ch, ch) for ch in text)


def _md_code_span(value: object) -> str:
    """Render untrusted text as a safe inline code span.

    Used for touched-file names: inside a backtick code span Markdown
    metacharacters are inert, so the break-out risk is an embedded backtick (or
    control char / newline). Strip those; additionally HTML-entity-escape angle
    brackets/ampersand so that even a renderer that emits the code-span content
    into HTML cannot surface an active tag (defence in depth for CWE-79)."""
    text = _MD_LINEBREAK_RX.sub(" ", str(value))
    text = _MD_INVISIBLE_RX.sub("", text)
    text = text.replace("`", "")
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return f"`{text}`"
