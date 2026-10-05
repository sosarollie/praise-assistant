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

"""Opt-in diagnostic logging for the vvaharness package: off by default, and every record is redacted."""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from vvaharness.report.redact import redact

__all__ = ["LEVELS", "configure"]

#: The package logger every module's ``getLogger(__name__)`` inherits from.
_ROOT = "vvaharness"

#: Accepted ``--log-level`` values, lowest to highest noise.
LEVELS: tuple[str, ...] = ("critical", "error", "warning", "info", "debug")

_FORMAT = "%(levelname)-8s %(name)s: %(message)s"


class _RedactingFormatter(logging.Formatter):
    """Formatter that masks secrets in the fully rendered line, catching credentials from any source."""

    def format(self, record: logging.LogRecord) -> str:
        return redact(super().format(record))


def configure(level: str | None = None, path: str | Path | None = None) -> bool:
    """Attach a redacting handler to the ``vvaharness`` logger; idempotent, and returns True when enabled."""
    chosen = (level or os.environ.get("VVAHARNESS_LOG_LEVEL") or "").strip().lower()
    if not chosen:
        return False
    numeric = getattr(logging, chosen.upper(), None)
    if not isinstance(numeric, int):
        print(f"  WARN: unknown log level {chosen!r}; expected one of {', '.join(LEVELS)}",
              file=sys.stderr)
        return False

    handler = _handler(path or os.environ.get("VVAHARNESS_LOG_FILE"))
    handler.setFormatter(_RedactingFormatter(_FORMAT))
    log = logging.getLogger(_ROOT)
    for existing in [h for h in log.handlers if getattr(h, "_vvaharness", False)]:
        log.removeHandler(existing)
    handler._vvaharness = True  # type: ignore[attr-defined]  # marks OUR handler for replacement
    log.addHandler(handler)
    log.setLevel(numeric)
    # Don't propagate to root, or a library consumer's own root handler would double every line.
    log.propagate = False
    return True


def _handler(path: str | Path | None) -> logging.Handler:
    """A file handler when *path* is usable, else stderr; never raises, since diagnostics can't sink a scan."""
    if not path:
        return logging.StreamHandler(sys.stderr)
    try:
        dest = Path(path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        return logging.FileHandler(dest, encoding="utf-8")
    except OSError as exc:
        print(f"  WARN: cannot open log file {path} ({exc}); logging to stderr",
              file=sys.stderr)
        return logging.StreamHandler(sys.stderr)
