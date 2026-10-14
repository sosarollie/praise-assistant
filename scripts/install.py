#!/usr/bin/env python3
"""Repository convenience wrapper for the installed Praise CLI."""
from pathlib import Path
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from praise.cli import main

if __name__ == "__main__":
    raise SystemExit(main(["install", *sys.argv[1:]]))
