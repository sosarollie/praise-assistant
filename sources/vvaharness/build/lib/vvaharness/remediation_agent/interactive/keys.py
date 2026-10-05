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

"""remediation_agent.interactive.keys — raw key input + decoding.

The dependency-free terminal key reader: :func:`decode_key` (a pure function
mapping a raw escape sequence to an UP/DOWN/ENTER/QUIT/OTHER token) and
:func:`_read_key` (POSIX/Windows raw-TTY reader). Raising on a non-TTY stream
lets the loop fall back to the numbered prompt."""
from __future__ import annotations

import sys

# Decoded key tokens the menu understands.
UP, DOWN, ENTER, QUIT, OTHER = "up", "down", "enter", "quit", "other"


def decode_key(seq: str) -> str:
    """Map a raw key sequence to one of the UP/DOWN/ENTER/QUIT/OTHER tokens.

    Pure function (no I/O) so it is unit-testable with a fake key stream.
    Handles arrow escape sequences (``\\x1b[A``/``\\x1b[B``), ``k``/``j`` vi-keys,
    Enter (CR/LF), and q/Esc/Ctrl-C/Ctrl-D as quit."""
    if seq in ("\x1b[A", "\x1bOA", "k"):
        return UP
    if seq in ("\x1b[B", "\x1bOB", "j"):
        return DOWN
    if seq in ("\r", "\n"):
        return ENTER
    if seq in ("q", "Q", "\x1b", "\x03", "\x04"):  # q, Esc, Ctrl-C, Ctrl-D
        return QUIT
    return OTHER


def _read_key() -> str:
    """Read one keypress (incl. multi-byte arrow escapes) from a POSIX/Windows
    TTY and return it decoded. Raises RuntimeError when no raw TTY is available
    so the caller can fall back to the numbered prompt."""
    if sys.platform == "win32":  # pragma: no cover - platform-specific
        try:
            import msvcrt
        except ImportError as e:
            raise RuntimeError("no raw keyboard input") from e
        ch = msvcrt.getwch()
        if ch in ("\x00", "\xe0"):           # arrow prefix on Windows
            ch2 = msvcrt.getwch()
            return {"H": UP, "P": DOWN}.get(ch2, OTHER)
        return decode_key(ch)

    import termios
    import tty
    if not sys.stdin.isatty():
        raise RuntimeError("stdin is not a TTY")
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
        if ch == "\x1b":                     # possible escape sequence
            ch += sys.stdin.read(2)
        return decode_key(ch)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
