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
"""s11_validate — thin wrapper that hooks the validation package (`vvaharness/validation/`) into the pipeline as a stage entry point."""
from __future__ import annotations

from collections.abc import MutableMapping
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vvaharness.config import Config


def run(  # noqa: PLR0913  # signature is the orchestrator's keyword contract (scan.py)
    repo: Path | str,
    *,
    cfg: Config,  # noqa: ARG001  # orchestrator passes cfg=cfg; keep the keyword accepted
    config_path: str,
    finding_ids: list[str] | None = None,
    resume: bool = False,
    report_md: Path | str | None = None,
    progress: MutableMapping[str, int] | None = None,
) -> int:
    """Invoke the s11 validation package against the case records s10 left under security-remediation/."""
    from vvaharness.validation.cli import main as validate_main
    argv = ["--repo", str(repo)]
    for flag, value in (("--config", config_path), ("--scan-report", report_md)):
        if value:
            argv += [flag, str(value)]
    for finding_id in finding_ids or ():
        argv += ["--finding", finding_id]
    if resume:
        argv.append("--resume")
    code = (validate_main(argv, progress=progress)
            if progress is not None else validate_main(argv))
    # Best-effort, like the manifest blocks: the rollup is reporting, so a failure in
    # it must never change the answer this stage gives. The import is inside the guard
    # for the same reason -- reaching case_rollup pulls in the whole orchestrator
    # package, and this stage's answer must not depend on that succeeding.
    try:
        from vvaharness.orchestrator import case_rollup
        case_rollup.record(repo)
    except Exception:
        pass
    return code
