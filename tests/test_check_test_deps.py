#!/usr/bin/env python3
"""Tests for tools/check_test_deps.py -- the precondition on every suite result.

WHY THIS SUITE EXISTS. On 2026-09-24 this repository's suite was run in a
checkout where `tests/requirements.txt` had never been installed. feedparser was
absent, `tests/test_estate_feeds_key.py` died on `import feedparser`, and
`tools/run_tests.sh` counted it the only way it could: FAIL. The result read
`pass=11 fail=1` and was reported -- in a merged pull request body and to the
repository's owner -- as a real, pre-existing failure of master. It was neither.
The same tree with the declared packages installed reads `pass=12 fail=0`.

That is the defect this gate closes, and it is a reporting defect rather than a
code one: a missing dependency is a fact about the machine, and the runner
presented it as a fact about the repository. The two are not interchangeable.
One is fixed by a pip install; the other sends somebody looking for a bug that
does not exist.

So the check runs BEFORE any suite, refuses the whole run, and names the
interpreter it judged -- because "feedparser is missing" is useless without
"missing from WHICH python", which is the actual mistake in a repo whose CI and
whose contributors use different ones.

WHAT IT DELIBERATELY DOES NOT DO. It judges presence, never the pin.
`tests/requirements.txt` pins `feedparser==6.0.11` to what `manifest.json`
ships, and enforcing that here would make a local run refuse over a patch
release while CI -- which installs the file verbatim -- is the thing that
actually holds the pin.

Run: python3 tests/test_check_test_deps.py
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
SCRIPT = os.path.join(ROOT, "tools", "check_test_deps.py")


def load(name, relpath):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, relpath))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


chk = load("ce_check_test_deps", "tools/check_test_deps.py")

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}: got {got!r}, want {want!r}")


def write(text):
    fd, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


def run(path):
    """Run the script as run_tests.sh runs it, and return (rc, stderr)."""
    proc = subprocess.run(
        [sys.executable, SCRIPT, path],
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stderr


# --- the name parser, on the shapes a requirements file actually carries ----

cases = [
    ("feedparser==6.0.11", ["feedparser"]),
    ("python-dateutil>=2.8.2", ["python-dateutil"]),
    ("pkg <= 2, >= 1", ["pkg"]),
    ("pkg~=1.0", ["pkg"]),
    ("pkg!=1.0", ["pkg"]),
    ("pkg[extra]==1.0", ["pkg"]),
    ("pkg; python_version < '3.12'", ["pkg"]),
    ("pkg  ==  1.0", ["pkg"]),
    ("  # a comment alone", []),
    ("feedparser==6.0.11  # trailing comment", ["feedparser"]),
    ("", []),
    ("   ", []),
    ("-r other.txt", []),
    ("--index-url https://example.invalid", []),
]
for line, want in cases:
    path = write(line + "\n")
    try:
        check(f"name parsed from {line!r}", chk.declared(chk.Path(path)), want)
    finally:
        os.unlink(path)

path = write("# header\nfeedparser==6.0.11\n\npython-dateutil>=2.8.2\n")
try:
    check("a whole file parses to both names",
          chk.declared(chk.Path(path)), ["feedparser", "python-dateutil"])
finally:
    os.unlink(path)

# --- the exit status, which is the only thing run_tests.sh reads ------------

path = write("this-package-does-not-exist-anywhere-0000\n")
try:
    rc, err = run(path)
    check("an absent package refuses the run", rc, 1)
    check("the refusal names the package",
          "this-package-does-not-exist-anywhere-0000" in err, True)
    check("the refusal names the interpreter it judged",
          sys.executable in err, True)
    check("the refusal says how to fix it", "pip install -r" in err, True)
    check("the refusal says it is CANNOT RUN, not a test failure",
          err.startswith("CANNOT RUN:"), True)
finally:
    os.unlink(path)

path = write("# nothing declared\n")
try:
    check("an empty file is not an error", run(path)[0], 0)
finally:
    os.unlink(path)

check("an absent requirements file is not an error",
      run(os.path.join(ROOT, "tests", "no-such-requirements.txt"))[0], 0)

# The repository's own file, against the interpreter running this suite. It
# passed the same check in run_tests.sh moments ago, so this must agree.
check("this repo's own tests/requirements.txt is satisfied here",
      run(os.path.join(ROOT, "tests", "requirements.txt"))[0], 0)

# A pin this interpreter cannot possibly satisfy still passes: presence only.
path = write("feedparser==0.0.0.0.1\n")
try:
    check("an unsatisfiable pin still passes -- presence is judged, not version",
          run(path)[0], 0)
finally:
    os.unlink(path)

# --- the wiring: run_tests.sh must actually call this ----------------------

runner = open(os.path.join(ROOT, "tools", "run_tests.sh"), encoding="utf-8").read()
check("run_tests.sh invokes the check",
      "tools/check_test_deps.py" in runner, True)
check("it invokes the check before running any suite",
      runner.index("tools/check_test_deps.py") < runner.index('for f in "${suites[@]}"'),
      True)

# --- self-test: prove the checks above can actually fail -------------------
print("\nSELF-TEST (these MUST report a failure to prove the gate works)")
_p, _f = PASS, FAIL
check("deliberately wrong equality", 1, 2)
path = write("this-package-does-not-exist-anywhere-0000\n")
try:
    check("the pre-gate behaviour, asserted: an absent package returns 0",
          run(path)[0], 0)
finally:
    os.unlink(path)
detected = FAIL - _f
PASS, FAIL = _p, _f
if detected == 2:
    PASS += 1
    print("  PASS  self-test: both deliberate failures were detected")
    print("        (the second IS the old behaviour: before this gate, an")
    print("         absent declared package reached the suites and came back")
    print("         as a red test rather than as a refusal to report)")
else:
    FAIL += 1
    print(f"  FAIL  self-test: expected 2 detected failures, saw {detected}")

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
