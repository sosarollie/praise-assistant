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

"""remediation_agent.options — parse the ``remediate`` command's CLI flags.

A small, dependency-light flag parser kept separate from the orchestration in
:mod:`vvaharness.remediation_agent.remediate` so flag handling is independently
testable. ``--top N`` parsing/validation lives in
:mod:`vvaharness.remediation_agent.select` and is reused here."""
from __future__ import annotations

from dataclasses import dataclass

from vvaharness.remediation_agent.select import parse_top_arg

VALID_MODES = ("fix", "report-only")


@dataclass(frozen=True)
class RemediateOptions:
    """Parsed ``remediate`` CLI flags. ``top`` is ``None`` when ``--top`` was
    not supplied (fall back to the profile's ``step_remediate.top_n_findings``),
    a positive int for an explicit cap, or the ``select.ALL_FINDINGS`` wildcard
    string when ``--top all`` / ``--top *`` was passed (remediate every
    finding, overriding any numeric profile cap)."""
    resume: bool = False
    interactive: bool = False
    verbose: bool = False
    mode: str = "fix"
    top: int | str | None = None


def parse_options(args: list[str]) -> RemediateOptions:
    """Build a :class:`RemediateOptions` from the raw argv slice.

    Raises :class:`ValueError` for an invalid ``--top``/``--mode`` so the caller
    can print a clean message and exit non-zero (mirrors argparse-style errors
    without pulling argparse into this hand-rolled flag set)."""
    mode = _mode_from(args)
    if mode not in VALID_MODES:
        raise ValueError(f"invalid --mode {mode!r}; choose one of {VALID_MODES}.")
    return RemediateOptions(
        resume="--resume" in args,
        interactive="--interactive" in args or "-i" in args,
        verbose="--verbose" in args or "-v" in args,
        mode=mode,
        top=parse_top_arg(args),  # may raise ValueError for a bad value
    )


def _mode_from(args: list[str]) -> str:
    """Parse ``--mode fix|report-only`` (split or ``=`` form). Default: fix."""
    for i, a in enumerate(args):
        if a == "--mode" and i + 1 < len(args):
            return args[i + 1]
        if a.startswith("--mode="):
            return a.split("=", 1)[1]
    return "fix"
