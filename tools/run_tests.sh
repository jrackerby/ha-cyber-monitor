#!/usr/bin/env bash
# Run every suite in tests/ and report a count.
#
# ASSERTS IT RAN SOMETHING. These suites moved repos, and a
# path assumption that did not survive the move would present as a clean run
# over zero files -- the vacuous green that is worse than a failure, because it
# reports the component as proven when nothing was executed.
#
# ASSERTS IT COULD HAVE RUN. tools/check_test_deps.py refuses the run when a
# package tests/requirements.txt declares is absent, because otherwise that
# environment fact arrives disguised as a red test in this repository. See its
# docstring for the 2026-09-24 measurement that is the reason it exists.
set -uo pipefail
cd "$(dirname "$0")/.."

shopt -s nullglob
suites=(tests/test_*.py)
if [ ${#suites[@]} -eq 0 ]; then
  echo "CANNOT RUN: no suites found in tests/ -- a green result here would assert nothing" >&2
  exit 1
fi

python3 tools/check_test_deps.py tests/requirements.txt || exit 1

pass=0
fail=0
for f in "${suites[@]}"; do
  if python3 "$f" > /tmp/ce_suite.out 2>&1; then
    echo "  PASS  $f"
    pass=$((pass + 1))
  else
    echo "  FAIL  $f"
    sed 's/^/        /' /tmp/ce_suite.out | tail -20
    fail=$((fail + 1))
  fi
done

echo "ran ${#suites[@]} suite(s): pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
