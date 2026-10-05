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

"""The parsed command line for ``vvaharness validate``."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

__all__ = ["ValidateArgs"]


@dataclass(frozen=True)
class ValidateArgs:
    """Every flag the parser accepts, so consumers read fields instead of probing a Namespace."""

    repo: Path
    config: str | None = None
    findings: tuple[str, ...] = ()
    every_validatable: bool = False
    max_findings: int | None = None
    workspace: Path | None = None
    resume: bool = False
    scan_report: Path | None = None

    @classmethod
    def of(cls, parsed: argparse.Namespace) -> ValidateArgs:
        """Build from an ``argparse`` result, normalising the repeatable and store_true flags."""
        return cls(
            repo=parsed.repo,
            config=parsed.config,
            findings=tuple(parsed.findings or ()),
            every_validatable=bool(parsed.all),
            max_findings=parsed.max_findings,
            workspace=parsed.workspace,
            resume=bool(parsed.resume),
            scan_report=parsed.scan_report,
        )
