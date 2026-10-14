#!/usr/bin/env python3
"""Standalone launcher so skillvet runs with no installation at all.

    ./skillvet.py scan .
    python3 skillvet.py scan ~/.claude/skills

Identical to the `skillvet` console command; both call skillvet.cli:main.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from skillvet.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
