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

"""Tripwires for the two schemas that are prompt text, and for the models package's leafness.

These guard the migration onto the shared contracts. A change that trips one of them is not
necessarily wrong, but it is never incidental: two of these schemas are interpolated into what
a model is asked to produce, so editing a field name there changes model behaviour and cannot
be measured -- this repo ships no eval harness.
"""
from __future__ import annotations

import ast
import json
import pathlib
import re
import subprocess
import sys

GOLDEN = pathlib.Path(__file__).parent / "fixtures" / "dto"

# Third-party distributions the contracts must never pull in. A caller depending on
# vvaharness.models for the types must not thereby install the agent stack.
_FORBIDDEN_DISTS = (
    "langchain",
    "langgraph",
    "deepagents",
    "anthropic",
    "openai",
    "claude_agent_sdk",
    "tree_sitter",
    "yaml",
)


def test_remediation_verdict_prompt_schema_unchanged():
    """The remediation verdict schema is embedded in the SYSTEM prompt; freeze it byte-exact."""
    from vvaharness.remediation_agent.models import RemediationVerdict

    expected = (GOLDEN / "remediation_verdict.prompt_schema.json").read_text(encoding="utf-8")
    assert RemediationVerdict.schema_json_compact() + "\n" == expected, (
        "RemediationVerdict's JSON schema changed. It is interpolated into the system prompt "
        "by vvaharness.remediation_agent.prompts, so this alters what the model is asked to "
        "emit. Re-record the golden only as a deliberate prompt change."
    )


def test_validation_output_schema_unchanged():
    """ValidationOutput is the structured-output schema for the validation session."""
    from vvaharness.validation.models.output import ValidationOutput

    expected = json.loads((GOLDEN / "validation_output.schema.json").read_text(encoding="utf-8"))
    assert ValidationOutput.model_json_schema() == expected, (
        "ValidationOutput's schema changed. It is the structured-output contract handed to "
        "the validation backend, so this alters model behaviour."
    )


#: vvaharness modules the contracts may depend on, each verified to import stdlib only.
#: vvaharness.report.cwe imports nothing but __future__, and report/__init__.py is empty.
# vvaharness.lang.hints is stdlib-only (re, pathlib), so it keeps the contracts a leaf.
_ALLOWED_INTERNAL = ("vvaharness.models", "vvaharness.report.cwe", "vvaharness.lang.hints")


def _imports_run_at_import_time(node):
    """Import nodes that execute when the module is imported — module and class bodies,
    including inside ``try``/``if``, but NOT inside a function body.

    The guarantee this tripwire protects is that ``import vvaharness.models`` pulls in no
    agent stack. A function-local import cannot affect that: it runs only if that function
    is called, which an embedder reading contracts never does. ``models/_scan.py`` uses one
    deliberately (and documents it) to render an exploit-verification repro block through
    the renderer that owns it, degrading to no block if the subsystem is absent.
    """
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue                      # deferred: not executed on import
        if isinstance(child, (ast.Import, ast.ImportFrom)):
            yield child
        yield from _imports_run_at_import_time(child)


def test_models_package_imports_only_stdlib_and_pydantic():
    """No module under vvaharness/models may reach into a non-leaf vvaharness subsystem at
    import time."""
    root = pathlib.Path(__file__).parent.parent / "vvaharness" / "models"
    offenders: list[str] = []
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in _imports_run_at_import_time(tree):
            module = _imported_module(node)
            if module and module.startswith("vvaharness.") and not module.startswith(
                _ALLOWED_INTERNAL
            ):
                offenders.append(f"{path.name} -> {module}")
    assert not offenders, (
        "the contracts must stay a leaf so an embedder can import them without the agent "
        f"stack; found: {offenders}. Add to _ALLOWED_INTERNAL only after verifying the "
        "target imports stdlib only, or defer the import into the function that needs it."
    )


def _imported_module(node: ast.AST) -> str | None:
    """Return the module an import node targets, or None if the node is not an import."""
    if isinstance(node, ast.ImportFrom):
        return node.module
    if isinstance(node, ast.Import):
        return node.names[0].name
    return None


def test_models_import_without_the_agent_stack():
    """vvaharness.models must import with the heavy distributions blocked at meta_path."""
    program = (
        "import sys\n"
        f"blocked = {_FORBIDDEN_DISTS!r}\n"
        "class Blocker:\n"
        "    def find_module(self, name, path=None):\n"
        "        return self.find_spec(name, path)\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name.split('.')[0] in blocked:\n"
        "            raise ImportError('blocked for this test: ' + name)\n"
        "        return None\n"
        "sys.meta_path.insert(0, Blocker())\n"
        "import vvaharness.models as m\n"
        "assert m.Finding is not None and m.FindingCase is not None\n"
        "print('ok')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", program],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(pathlib.Path(__file__).parent.parent),
    )
    assert result.returncode == 0 and "ok" in result.stdout, (
        f"vvaharness.models could not import with the agent stack blocked:\n{result.stderr}"
    )


# Redaction ordering: redact() must see the WHOLE text, never a truncated slice.
#
# This is a source-level tripwire because the defect is invisible at runtime on
# normal input -- it only leaks when a credential happens to straddle the cut, so
# no ordinary test run would ever notice. Truncating first bisects the secret, and
# the surviving prefix no longer matches any pattern in report.redact, so it is
# emitted UNMASKED into an exception message, a log line, an errlog entry, or a
# delivered report -- under text that advertises the content as redacted.
#
# Correct:   redact(body)[:400]        Wrong: redact(body[:400])
# Correct:   _tail(redact(stderr))     Wrong: redact(_tail(stderr))
#
# Helpers that shorten text, so redact() must wrap them rather than the reverse.
_TRUNCATING_HELPERS = frozenset({"_tail", "_cap_text", "_head", "_truncate"})

# An exact helper denylist cannot be complete (any new helper name evades it),
# so unknown callee names are ALSO matched by identifier segment: a function
# whose snake_case/camelCase name contains one of these words is treated as
# truncating (e.g. shorten, clip_text, capText, textwrap.shorten). Segments —
# not substrings — so "escape" does not match "cap" and "capitalize" does not
# match "cap". Still a heuristic: see the limitation note in the tripwire
# test's docstring.
_TRUNCATING_NAME_SEGMENTS = frozenset({
    "tail", "head", "trunc", "truncate", "truncated", "cap", "capped",
    "shorten", "shortened", "clip", "clipped", "snip", "abbrev",
    "abbreviate", "excerpt", "elide", "elided", "ellipsize", "limit",
})


def _is_truncating_helper_name(name: str) -> bool:
    """True if `name` is a known truncating helper or reads like one."""
    if name in _TRUNCATING_HELPERS:
        return True
    segments = {
        s.lower()
        for part in name.split("_")
        for s in re.findall(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])", part)
    }
    return bool(segments & _TRUNCATING_NAME_SEGMENTS)


def _truncating_expr(node: ast.AST) -> str | None:
    """Describe `node` if it shortens text (so it must not feed redact), else None.

    redact(x)[:n] -- a slice OVER a redact call -- is the correct order and
    is exempt; a plain index (x[0]) is not a truncation, so only Slice
    subscripts count.
    """
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice):
        return None if _is_redact_call(node.value) else "<sliced>"
    if isinstance(node, ast.Call):
        # whole_or_nothing=True is the repo's explicit NON-truncating mode
        # (see s2_threatmodel._read_capped: it returns "" instead of a
        # truncated prefix, precisely so callers can redact the result).
        for kw in node.keywords:
            if (kw.arg == "whole_or_nothing"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True):
                return None
        func = node.func
        name = (func.id if isinstance(func, ast.Name)
                else func.attr if isinstance(func, ast.Attribute) else None)
        if name and name not in _REDACT_NAMES and _is_truncating_helper_name(name):
            return f"{name}(...)"
    return None

# The redacting entry points of vvaharness.report.redact. All three have the
# same ordering requirement: handing any of them pre-shortened text bisects a
# secret before the patterns ever see it.
_REDACT_NAMES = frozenset({"redact", "redact_counts", "redact_tree"})

# Every module that hands provider/model/subprocess text to a redact entry
# point OR to errlog.log (which redacts its string fields internally, so it
# has the same ordering requirement). Add new ones here; the point of the
# tripwire is that it fails when the next module repeats the mistake, not
# just when these regress. The list is the grep-derived union, over the WHOLE
# vvaharness tree, of
#   grep -rln 'redact(\|redact_counts(\|redact_tree(' vvaharness/
#   grep -rln '_errlog\.log\|errlog\.log' vvaharness/
# (report/redact.py is the definition site, listed so its internal calls are
# scanned like any caller's; s5_prefilter calls none of these and is
# deliberately absent).
# test_redaction_caller_list_is_complete re-derives that union and fails if
# any file in the tree starts calling redact*/errlog.log without being listed
# here, so the list cannot silently drift behind the tree.
_REDACTION_CALLERS = (
    "pipeline/stages/callgraph_engine/_annotator.py",
    "backends/harness/deepagents/redaction.py",
    "backends/llm/agent_sdk.py",
    "backends/llm/cache.py",
    "backends/llm/cli.py",
    "backends/llm/deepagents.py",
    "backends/llm/sdk.py",
    "backends/llm/openai.py",
    "backends/llm/tools.py",
    "exploit_verification/safety.py",
    "injectors/cve_feed.py",
    "injectors/design_controls.py",
    "manifest.py",
    "orchestrator/batch.py",
    "orchestrator/entry.py",
    "orchestrator/findings_json.py",
    "orchestrator/preflight.py",
    "orchestrator/scan.py",
    "pipeline/stages/s1_autoexclude.py",
    "pipeline/stages/s1_preprocess.py",
    "pipeline/stages/s2_threatmodel.py",
    "pipeline/stages/s3_decompose.py",
    "pipeline/stages/s4_deepdive.py",
    "pipeline/stages/s6_verify.py",
    "pipeline/stages/s7_dedup.py",
    "pipeline/stages/s8_chain.py",
    "remediation_agent/artifacts/writer.py",
    "remediation_agent/interactive/loop.py",
    "remediation_agent/plugin_runner/trace.py",
    "remediation_agent/runner.py",
    "report/enrich.py",
    "report/redact.py",
    "util/errlog.py",
    "util/logs.py",
    "util/response_quality.py",
    "util/scan_progress.py",
    "util/status.py",
    "validation/cli/_run.py",
    "validation/models/output.py",
    "validation/session/launcher.py",
)


def test_redaction_caller_list_is_complete():
    """Anti-drift guard for _REDACTION_CALLERS (the tripwire's blind spot).

    The deepagents backend shipped with correct redact(body)[:400] ordering
    but was invisible to the ordering tripwire below because nobody added it
    to the list — exactly the drift this test now makes impossible.

    Derivation is the WHOLE vvaharness tree, deliberately. It used to be
    scoped to pipeline/stages + backends/llm ("where provider/model text is
    handled"), and that scoping is exactly how a truncate-then-redact leak
    shipped in util/errlog.py: errlog writes redacted exception/traceback
    text — which routinely embeds provider stderr and repo content — to
    errors.jsonl on disk, but lived outside both domains, so the ordering
    tripwire never parsed it. The tree-wide sweep costs ~0.3s over ~260 files
    and, at the time of widening, flagged exactly one offender (that errlog
    bug, since fixed) and zero false positives, so the wider net does not
    erode trust in the check.

    One-directional on purpose: a listed file that stops calling redact*() is
    harmless (it is scanned and yields no offenders), but an unlisted caller
    is an unguarded emitting path.
    """
    root = pathlib.Path(__file__).parent.parent / "vvaharness"
    # "errlog.log" also matches _errlog.log; the redact needles cover all
    # three entry points ("redact(" alone would miss redact_tree/redact_counts).
    needles = tuple(f"{n}(" for n in _REDACT_NAMES) + ("errlog.log",)
    found: set[str] = set()
    for path in sorted(root.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        if any(n in text for n in needles):
            found.add(path.relative_to(root).as_posix())
    missing = sorted(found - set(_REDACTION_CALLERS))
    assert not missing, (
        "these modules call redact*()/errlog.log but are not in "
        f"_REDACTION_CALLERS, so the ordering tripwire never sees them: {missing}"
    )


def _is_redact_call(node: ast.AST) -> bool:
    """True for a direct redact*(...) call -- redact(x)[:n] is the CORRECT order.

    A constant-index subscript over the call is unwrapped first so that
    redact_counts(x)[0][:n] -- the correct order for the tuple-returning
    variant -- stays exempt like redact(x)[:n].
    """
    if isinstance(node, ast.Subscript) and not isinstance(node.slice, ast.Slice):
        node = node.value
    return (isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in _REDACT_NAMES)


def _walk_scope(node: ast.AST):
    """Yield descendants of `node` without entering nested function scopes."""
    todo = list(ast.iter_child_nodes(node))
    while todo:
        n = todo.pop()
        yield n
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            todo.extend(ast.iter_child_nodes(n))


def _truncated_names(scope: ast.AST) -> dict[str, str]:
    """Map names assigned a truncating expression IN THIS SCOPE to a description.

    Catches the intermediate-variable evasion (t = body[:400]; redact(t)) that
    the direct-argument check cannot see. Lexical per scope, not flow-sensitive:
    a name is tainted if ANY assignment in the scope gives it truncated text
    (Assign/AnnAssign/walrus with a simple Name target). That over-approximates
    -- a later clean reassignment of the same name would also be flagged --
    which is the right bias for a tripwire; scoping per function (plus module
    globals) keeps a same-named local in an unrelated function from tainting,
    and the tree-wide false-positive sweep keeps the heuristic honest.
    """
    tainted: dict[str, str] = {}
    for node in _walk_scope(scope):
        target = value = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            target, value = node.target, node.value
        elif isinstance(node, ast.NamedExpr):
            target, value = node.target, node.value
        if isinstance(target, ast.Name) and value is not None:
            desc = _truncating_expr(value)
            if desc:
                tainted.setdefault(target.id, f"{desc} at line {node.lineno}")
    return tainted


def _shortened_input(arg: ast.AST, tainted: dict[str, str]) -> str | None:
    """Describe how `arg` hands pre-shortened text to a redacting sink, else None.

    Three shapes: a truncating expression inline (x[:n], _tail(x), shorten(x)),
    a bare name previously assigned one (the intermediate-variable evasion),
    and an f-string embedding either (redact(f"{body[:400]}") shortens just as
    surely as redact(body[:400]) -- the JoinedStr wrapper hid it from the old
    direct-argument check).
    """
    desc = _truncating_expr(arg)
    if desc:
        return desc
    if isinstance(arg, ast.Name) and arg.id in tainted:
        return f"variable {arg.id!r} = {tainted[arg.id]}"
    if isinstance(arg, ast.JoinedStr):
        for sub in ast.walk(arg):
            desc = _truncating_expr(sub)
            if desc:
                return f"f-string embedding {desc}"
            if isinstance(sub, ast.Name) and sub.id in tainted:
                return f"f-string embedding variable {sub.id!r} = {tainted[sub.id]}"
    return None


def _redact_arg_offenders(path: pathlib.Path) -> list[str]:
    """Return a description of every redact()/errlog.log() call handed pre-shortened text."""
    offenders: list[str] = []
    tree = ast.parse(path.read_text(encoding="utf-8"))
    # One taint map per scope: module-level names are visible everywhere, a
    # function's locals only within it (closure capture from an enclosing
    # function is not followed -- a tripwire, not a type system).
    module_taint = _truncated_names(tree)
    scopes: list[tuple[ast.AST, dict[str, str]]] = [(tree, module_taint)]
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scopes.append((fn, {**module_taint, **_truncated_names(fn)}))
    for scope, tainted in scopes:
        offenders.extend(_scope_offenders(path, scope, tainted))
    return offenders


def _scope_offenders(path: pathlib.Path, scope: ast.AST,
                     tainted: dict[str, str]) -> list[str]:
    """Flag redact()/errlog.log() calls directly in `scope` handed shortened text."""
    offenders: list[str] = []
    for node in _walk_scope(scope):
        if not isinstance(node, ast.Call):
            continue
        # -- redact*(<pre-shortened>) ------------------------------------------
        if (isinstance(node.func, ast.Name) and node.func.id in _REDACT_NAMES
                and node.args):
            desc = _shortened_input(node.args[0], tainted)
            if desc:
                offenders.append(
                    f"{path.name}:{node.lineno}: {node.func.id}({desc}) -- "
                    f"shorten AFTER redact, never before"
                )
        # -- errlog.log(..., kw=<pre-shortened>) --------------------------------
        # errlog.log redacts its string fields INTERNALLY, but only after
        # receiving them, so it has the same ordering requirement as redact():
        # a kwarg truncated at the call site (raw_head=raw[:500], or via an
        # intermediate variable / f-string) is shortened before that internal
        # redaction and a bisected secret lands in errors.jsonl unmasked.
        # redact(x)[:n] as the kwarg is the correct order and is exempt.
        if (isinstance(node.func, ast.Attribute) and node.func.attr == "log"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in ("errlog", "_errlog")):
            for kw in node.keywords:
                desc = _shortened_input(kw.value, tainted)
                if desc:
                    offenders.append(
                        f"{path.name}:{node.lineno}: errlog.log({kw.arg}={desc}) -- "
                        f"errlog redacts internally AFTER this truncation; "
                        f"pass {kw.arg}=redact(...)[:n] instead"
                    )
    return offenders


def test_redact_is_never_handed_pre_truncated_text():
    """REGRESSION: redact(body[:400]) and redact(_tail(x)) leaked partial credentials.

    Both shapes shipped: a JWT whose third segment was cut below the pattern's
    minimum length stopped matching and reached an AuthenticationError verbatim,
    and _tail() keeps only the LAST n chars, so redacting the tail dropped a
    token's leading `eyJ` anchor and left the remainder unmasked.

    A third shape also shipped, in two stage modules at once (s2's repair
    fallback and s6's unparseable-verdict path): errlog.log(..., raw_head=raw[:500])
    -- errlog redacts internally, but only after the caller already truncated,
    so the bisected prefix reached errors.jsonl unmasked. A fourth instance
    shipped inside util/errlog.py itself: log() tail-sliced the traceback to
    its last 4000 chars BEFORE its internal redact(), dropping a straddling
    credential's leading anchor -- and lived outside the derivation scope this
    tripwire had at the time, which is why the scope is now the whole tree
    (see test_redaction_caller_list_is_complete). NOTE: a print that
    never calls redact at all (s1's old fallback) is invisible to this AST
    check; the per-stage behavioural regression tests cover that shape.

    Also caught: the intermediate-variable evasion (t = body[:400]; redact(t))
    and f-string slices (redact(f"{body[:400]}")). KNOWN LIMITATION: helper
    calls are matched by the exact _TRUNCATING_HELPERS names plus the
    _TRUNCATING_NAME_SEGMENTS identifier heuristic (shorten, clip_text, ...).
    An open-ended helper denylist cannot be complete -- a truncating helper
    with an opaque name (e.g. redact(fmt(body)) where fmt slices internally)
    still evades this AST check, as does any multi-step flow the lexical
    variable pass cannot follow. This tripwire is a cheap source-level net,
    not proof of absence; the behavioural leak tests (e.g.
    test_extract_yaml_parse_error_never_leaks_secret_fragment_to_stderr in
    tests/test_s1_autoexclude.py) are the ground truth for each emitting path.
    """
    root = pathlib.Path(__file__).parent.parent / "vvaharness"
    offenders: list[str] = []
    for rel in _REDACTION_CALLERS:
        path = root / rel
        assert path.is_file(), f"tripwire points at a moved file: {rel}"
        offenders.extend(_redact_arg_offenders(path))
    assert not offenders, (
        "redact() must receive the full text and be truncated AFTER, never before:\n  "
        + "\n  ".join(offenders)
    )
