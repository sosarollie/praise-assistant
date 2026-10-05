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

"""Wave-1 documentation tripwires.

Docs cannot derive from code the way the doctor message derives from
``DEEPAGENTS_ROLES`` (``environment.py`` builds its role list from the
frozenset, so it can never drift; a Markdown file can). Each test here pins a
claim that *did* go stale — nine doc sites plus the ``agentdoc.py`` generator
shipped "``verify``/``deepdive`` reject ``via: deepagents``" long after both
roles were admitted — or that was found outright false at open-source release
review (the README coverage "guarantee", the "every marker on every route"
cache kill-switch claim). Greps are the substitute for derivation: crude, but
they fail the moment the retracted wording returns.
"""
from __future__ import annotations

import re
from pathlib import Path

from vvaharness.agentdoc import AGENT_DOC
from vvaharness.backends.llm.registry import DEEPAGENTS_ROLES

_REPO = Path(__file__).resolve().parents[1]
_DOC_FILES = sorted((_REPO / "docs").glob("*.md")) + [
    _REPO / "README.md",
    _REPO / "SECURITY.md",
]

# Words that, next to "deepagents" and a role name, assert the role cannot
# take the route. "no `deepagents`" was the models.md matrix spelling.
_REJECTION_RX = re.compile(
    r"reject|fatal at preflight|immediate exit|no `deepagents`", re.I
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_doc_files_exist():
    # If the layout moves, the greps below would vacuously pass — fail loudly
    # instead of silently checking nothing.
    assert len(_DOC_FILES) > 5, _DOC_FILES


def test_agent_doc_never_names_an_admitted_role_as_excluded():
    """The generator instance of the stale role-gate claim.

    ``setup --install-agents`` writes AGENT_DOC into every operator repo and
    never overwrites, so a stale exclusion here outlives the fix in-tree.
    """
    for role in sorted(DEEPAGENTS_ROLES):
        assert not re.search(rf"other than[^.\n]*`{role}`", AGENT_DOC), (
            f"AGENT_DOC excludes `{role}`, which is in DEEPAGENTS_ROLES"
        )
        assert f"rejected on `{role}`" not in AGENT_DOC, role


def test_docs_never_claim_an_admitted_role_rejects_deepagents():
    """No doc line may pair an admitted role with a deepagents rejection."""
    offenders: list[str] = []
    for path in _DOC_FILES:
        for lineno, line in enumerate(_read(path).splitlines(), 1):
            if "deepagents" not in line.lower():
                continue
            if not _REJECTION_RX.search(line):
                continue
            named = [r for r in sorted(DEEPAGENTS_ROLES) if f"`{r}`" in line]
            if named:
                offenders.append(
                    f"{path.relative_to(_REPO)}:{lineno} names {named}: "
                    f"{line.strip()[:120]}"
                )
    assert not offenders, "\n".join(offenders)


def test_docs_never_reclaim_the_coverage_guarantee():
    """The retracted README claim: the catch-all backstop has a deliberate
    skip list (``_CATCHALL_SKIP_*`` in ``s3_decompose.py``), so 'no in-scope
    file reaches zero reviewers' is refutable from this repo's own source."""
    for path in _DOC_FILES:
        assert "no in-scope file reaches zero reviewers" not in _read(path), (
            f"{path} re-asserts the retracted coverage guarantee"
        )
    # The docs sweep alone missed the worst instance: the phrase also lived in
    # the report *renderer*, so every scan kept printing the guarantee at an
    # operator months after the prose retracted it. Pin the renderer too, not
    # only the prose that describes it.
    assert "guaranteed coverage" not in _read(_REPO / "vvaharness/models/_scan.py"), (
        "the Pipeline Diagnostics label re-asserts the retracted guarantee"
    )


# The files that translate outcomes into process exit codes. Deliberately a
# short, named list rather than a package-wide sweep: in these three files
# every bare `return <int>` *is* an exit code, so the AST scan below stays
# honest. A count-returning helper added to one of them would false-positive —
# keep such helpers elsewhere, or extend the docs table.
_EXIT_CODE_SOURCES = (
    "vvaharness/cli.py",
    "vvaharness/orchestrator/entry.py",
    "vvaharness/orchestrator/batch.py",
)


def _returned_exit_codes() -> set[int]:
    import ast

    codes: set[int] = set()
    for rel in _EXIT_CODE_SOURCES:
        for node in ast.walk(ast.parse(_read(_REPO / rel))):
            if (
                isinstance(node, ast.Return)
                and isinstance(node.value, ast.Constant)
                and type(node.value.value) is int  # excludes bool
            ):
                codes.add(node.value.value)
    return codes


def test_docs_publish_every_exit_code_the_cli_returns():
    """Every exit code the CLI actually returns has a row in the
    docs/outputs.md contract table.

    Direction matters and is one-way by design: code → docs. The docs may
    legitimately publish a code *before* the commit that returns it lands
    (the table documented ``3`` ahead of the code), so the reverse
    assertion (docs → code) must never be added here.
    """
    table_codes = {
        int(m)
        for m in re.findall(
            r"^\| `(\d+)` \|", _read(_REPO / "docs/outputs.md"), re.M
        )
    }
    from vvaharness.orchestrator.case_rollup import EXIT_NOT_REMEDIATED

    returned = _returned_exit_codes()
    # The AST scan cannot see a code that reaches the process through a variable
    # (entry.py returns outcome.exit_code), so the one code that travels that way is
    # pinned by its constant instead of by a literal search.
    returned.add(EXIT_NOT_REMEDIATED)
    # If either side comes back empty the assertion below would vacuously
    # pass — fail loudly instead of silently checking nothing.
    assert 130 in returned and 2 in returned, returned
    assert 0 in table_codes and 130 in table_codes, table_codes
    missing = returned - table_codes
    assert not missing, (
        f"the CLI returns exit codes with no row in docs/outputs.md's "
        f"Exit codes table: {sorted(missing)}"
    )


def test_docs_never_reclaim_the_universal_cache_kill_switch():
    """The retracted cache claim: ``cache_markers: off`` does not gate the
    deepagents route's middleware markers, so 'every marker on every route'
    was false. Docs must scope the switch to the cli/sdk/openai routes."""
    for path in _DOC_FILES:
        assert "every marker on every route" not in _read(path), (
            f"{path} re-asserts the universal cache kill-switch claim"
        )


def test_ev_safety_markers_present_in_front_door_docs():
    """EV front-door safety content regressed once (a6b90ea deleted it in 72h) with
    no test failing. Pin the markers — not exact prose — so the retracted content
    cannot silently vanish again. Presence only — enforcement behaviour is covered by
    the exploit-verification safety tests, not here."""
    readme = _read(_REPO / "README.md")
    assert "## Exploit verification" in readme          # section heading + Beta label
    assert "Beta" in readme and "localhost" in readme   # label + destination framing

    security = _read(_REPO / "SECURITY.md").lower()
    assert "exploit verification" in security and "loopback" in security

    sec_doc = _read(_REPO / "docs" / "security.md").lower()
    assert "exploit verification" in sec_doc and "loopback" in sec_doc
