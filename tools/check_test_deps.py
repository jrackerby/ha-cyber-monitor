#!/usr/bin/env python3
"""Refuse to report a suite result when a declared dependency is absent.

tests/requirements.txt is declared beside the suite and CI installs it. A
checkout that has not lands a bare ModuleNotFoundError inside whichever suite
imports the missing package, and tools/run_tests.sh counts that as FAIL -- so
an environment fact arrives disguised as a red test in this repository.

Measured 2026-09-24: an uninstalled feedparser presented as "pass=11 fail=1,
the pre-existing test_estate_feeds_key.py" and was reported as a real,
pre-existing failure of master. It was neither. With the declared packages
installed the same tree reads pass=12 fail=0.

This runs before any suite does, names the interpreter it checked, and says
what to install. It judges presence only; the pin is CI's business.
"""

from __future__ import annotations

import re
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

# A requirement line's name is everything before the first version specifier,
# extra, marker or comment. Enough for a plain pinned list; this is a
# precondition check, not a PEP 508 parser.
_NAME = re.compile(r"[^<>=!~\[;\s]+")


def declared(path: Path) -> list[str]:
    names = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        match = _NAME.match(line)
        if match:
            names.append(match.group(0))
    return names


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("tests/requirements.txt")
    if not path.is_file():
        # Nothing declared is not an error: a suite with no third-party
        # imports has nothing to check.
        return 0

    names = declared(path)
    if not names:
        return 0

    missing = []
    for name in names:
        try:
            version(name)
        except PackageNotFoundError:
            missing.append(name)

    if not missing:
        return 0

    print(
        f"CANNOT RUN: {path} declares packages this interpreter does not have: "
        + ", ".join(missing),
        file=sys.stderr,
    )
    print(f"            interpreter: {sys.executable}", file=sys.stderr)
    print(
        "            Without them a suite reports FAIL and the failure reads as",
        file=sys.stderr,
    )
    print("            this repository's rather than the environment's:", file=sys.stderr)
    print(f"              {sys.executable} -m pip install -r {path}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
