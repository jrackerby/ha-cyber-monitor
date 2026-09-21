#!/usr/bin/env python3
"""Every sweep this integration runs must keep what it found.

THE DEFECT THIS SUITE EXISTS FOR (GH-31). `async_request_scan("discovery")` --
the Scan now button's local-mode path -- ran a real sweep of the whole
configured scope, stamped `_last_discovery`, and then never called
`store.apply_scan`. The `ScanResult` was not even bound to a name. So the
press cost a sweep on the wire, suppressed the NEXT scheduled sweep for a full
discovery interval, and recorded nothing: plug in a new device, press Scan now,
see nothing, and wait an hour for the sweep that would actually have noticed.

It is a hard failure to see by reading. The function is not obviously wrong --
it loads the store and republishes the view, which looks like the end of a
normal sweep -- and `InventoryStore.async_load` returns early once loaded, so
the reload is a no-op that reads like the merge. It came in with the initial
import and survived every later change to the file.

SO THE GATE IS STRUCTURAL, NOT TEXTUAL. This suite walks `coordinator.py`'s
AST and asserts an invariant the next author cannot miss by copying a block:
every method that runs `self.scanner.async_scan` must BIND the result and must
hand it to something that keeps it. A fourth scan path that forgets fails here
rather than in production, silently, a year later.

The second half is the pruning policy, which is the thing the three paths
legitimately differ on and therefore the thing most likely to be got wrong:
SCHEDULED SWEEPS AGE THE INVENTORY, OPERATOR-INITIATED ONES NEVER DO. Getting
that backwards destroys `first_seen` for hosts that were merely switched off
when somebody happened to press a button, and no amount of rescanning brings
it back.

THE SELF-TEST AT THE END PROVES THESE CHECKS CAN FAIL.

Run: python3 tests/test_cyber_estate_scan_apply.py
"""

from __future__ import annotations

import ast
import importlib.util
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
COMPONENT = os.path.join(HERE, "..")
PKG = os.path.join(COMPONENT, "scan")

# A REAL PACKAGE, not an orphan module -- parse.py is loaded below for the one
# behavioural check, and it imports from const.py by relative import.
_pkg = types.ModuleType("ce_scan")
_pkg.__path__ = [PKG]
sys.modules["ce_scan"] = _pkg


def load(name, filename):
    spec = importlib.util.spec_from_file_location(
        f"ce_scan.{name}", os.path.join(PKG, filename)
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[f"ce_scan.{name}"] = mod
    spec.loader.exec_module(mod)
    return mod


parse = load("parse", "parse.py")

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}\n          got  {got!r}\n          want {want!r}")


# --- the AST, and a scraper that is itself pinned --------------------------
#
# coordinator.py imports Home Assistant, so it is PARSED, never imported. Every
# check below is a set difference or a membership test, and a scraper that
# found nothing would pass most of them vacuously -- so the scraper's own
# output is asserted first, against the method names this file names in prose.

_SOURCE = os.path.join(PKG, "coordinator.py")
_TREE = ast.parse(open(_SOURCE).read())

_LOCAL = next(
    node
    for node in _TREE.body
    if isinstance(node, ast.ClassDef) and node.name == "LocalCoordinator"
)
_METHODS = {
    node.name: node
    for node in _LOCAL.body
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
}


def dotted(node: ast.AST) -> str | None:
    """`self.store.apply_scan` from the Call's func, or None."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def calls_in(method: ast.AST) -> set[str]:
    out = set()
    for node in ast.walk(method):
        if isinstance(node, ast.Call):
            name = dotted(node.func)
            if name:
                out.add(name)
    return out


SCAN = "self.scanner.async_scan"
# Anything that takes a ScanResult and does not drop it on the floor.
KEEPERS = {
    "self.store.apply_scan",
    "self._fold_in_full_sweep",
    "self.async_run_custom_scan",
}

_scanners = sorted(n for n, m in _METHODS.items() if SCAN in calls_in(m))

print("the scraper found the methods this suite is about")
check("every local-mode method that runs nmap",
      _scanners,
      ["_run_discovery", "_run_service_scan", "async_request_scan",
       "async_run_custom_scan"])
check("LocalCoordinator was actually located",
      "_fold_in_full_sweep" in _METHODS, True)


def scan_results_bound(method: ast.AST) -> list[str]:
    """The names each `self.scanner.async_scan(...)` result is bound to."""
    out = []
    for node in ast.walk(method):
        if not isinstance(node, ast.Assign):
            continue
        value = node.value
        if isinstance(value, ast.Await):
            value = value.value
        if not (isinstance(value, ast.Call) and dotted(value.func) == SCAN):
            continue
        out += [t.id for t in node.targets if isinstance(t, ast.Name)]
    return out


def names_reaching_keepers(method: ast.AST) -> set[str]:
    """Every name passed to something that keeps a ScanResult.

    Walks each keeper call's arguments rather than matching the argument
    text, so `result`, `result.hosts` and `f(result)` all count -- what is
    being asserted is that the binding is USED, not how.
    """
    out: set[str] = set()
    for node in ast.walk(method):
        if not isinstance(node, ast.Call) or dotted(node.func) not in KEEPERS:
            continue
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            for inner in ast.walk(arg):
                if isinstance(inner, ast.Name):
                    out.add(inner.id)
    return out


# --- the invariant ---------------------------------------------------------
#
# THE METHOD-LEVEL VERSION OF THIS CHECK IS NOT ENOUGH, and the defect is why:
# `async_request_scan` has two branches, and the one that was throwing its
# sweep away sat beside one that calls `async_run_custom_scan` -- so "this
# method calls a keeper somewhere" was TRUE of the broken code. The binding
# itself has to be followed.
print("\nno path may run a sweep and then discard what it found")
for _name in _scanners:
    _bound = scan_results_bound(_METHODS[_name])
    _used = names_reaching_keepers(_METHODS[_name])
    check(f"{_name}: binds its sweep's result", bool(_bound), True)
    check(f"{_name}: and every binding reaches something that keeps it",
          sorted(set(_bound) - _used), [])


def bare_scan_calls(method: ast.AST) -> list[int]:
    """Line numbers where the scan's result is thrown away.

    THE EXACT SHAPE OF GH-31: `await self.scanner.async_scan(...)` as a
    statement of its own. A `ScanResult` that is never bound cannot be merged,
    and nothing downstream can notice that it was not -- the store simply
    still holds what it held before the sweep.
    """
    out = []
    for node in ast.walk(method):
        if not isinstance(node, ast.Expr):
            continue
        inner = node.value
        if isinstance(inner, ast.Await):
            inner = inner.value
        if isinstance(inner, ast.Call) and dotted(inner.func) == SCAN:
            out.append(node.lineno)
    return out


print("\nand the result must be BOUND, not evaluated and dropped")
for _name in _scanners:
    check(f"{_name}: no unbound scan call",
          bare_scan_calls(_METHODS[_name]), [])

# --- the pruning policy ----------------------------------------------------
#
# The one thing the three full-sweep paths legitimately differ on, and so the
# one most worth pinning: forgetting a host destroys `first_seen`, which is
# unrecoverable, so it belongs to the clock that runs unattended rather than
# to a button somebody pressed for an unrelated reason.


def fold_calls(method: ast.AST) -> list[bool]:
    """The `prune=` argument of each `_fold_in_full_sweep` call, in order."""
    out = []
    for node in ast.walk(method):
        if not isinstance(node, ast.Call):
            continue
        if dotted(node.func) != "self._fold_in_full_sweep":
            continue
        for kw in node.keywords:
            if kw.arg == "prune":
                out.append(kw.value.value)
    return out


print("\nscheduled sweeps age the inventory; operator-initiated ones never do")
check("the scheduled discovery sweep prunes",
      fold_calls(_METHODS["_run_discovery"]), [True])
check("the scheduled service sweep prunes",
      fold_calls(_METHODS["_run_service_scan"]), [True])
check("the Scan now discovery sweep does NOT prune",
      fold_calls(_METHODS["async_request_scan"]), [False])
check("prune is keyword-only, so no call site can pass it by position",
      bool(_METHODS["_fold_in_full_sweep"].args.kwonlyargs), True)
check("and it has no default, so no call site can omit the decision",
      _METHODS["_fold_in_full_sweep"].args.kw_defaults, [None])

# ONE MERGE SITE PER POLICY. Two is the whole count: the shared fold-in for
# whole-scope sweeps, and `async_run_custom_scan` for the narrow on-demand
# case. A third would be a fourth copy of a rule that has already drifted once.
_applies = sorted(
    n for n, m in _METHODS.items() if "self.store.apply_scan" in calls_in(m)
)
check("exactly two methods merge a scan into the store",
      _applies, ["_fold_in_full_sweep", "async_run_custom_scan"])
check("the narrow on-demand path still refuses to prune",
      "stale_days=None" in ast.get_source_segment(
          open(_SOURCE).read(), _METHODS["async_run_custom_scan"]
      ), True)

# --- the clock must not move without the merge -----------------------------
#
# The two go together: stamping `_last_discovery` suppresses the next scheduled
# sweep for a full interval, so a path that stamps it and merges nothing costs
# the operator the sweep that WOULD have recorded the answer. That is precisely
# what the Scan now button did.
print("\nnothing may move the discovery clock without folding a sweep in")
for _name, _method in _METHODS.items():
    _src = ast.get_source_segment(open(_SOURCE).read(), _method) or ""
    if "self._last_discovery = dt_util.utcnow()" not in _src:
        continue
    check(f"{_name}: stamps the clock and keeps the sweep",
          bool(calls_in(_method) & KEEPERS), True)

# --- what the discarded result actually was --------------------------------
#
# Pure layer, so the cost is demonstrated rather than asserted: the merge the
# button skipped is the only thing that creates a host record at all, and the
# only thing that gives it the `first_seen` the unknown-host detector reads.
print("\nthe merge that was skipped is what creates a record in the first place")
_swept = {
    "aa": {
        "key": "aa",
        "mac": "AA:BB:CC:DD:EE:FF",
        "ip": "192.0.2.51",
        "ports_scanned": False,
    }
}
_inv, _new, _changed = parse.merge_inventory({}, _swept)
check("folding the sweep in is what creates the host", _new, ["aa"])
check("and what gives it a first_seen",
      bool(_inv["aa"].get("first_seen")), True)
check("and its last_seen", bool(_inv["aa"].get("last_seen")), True)
# The counterfactual, stated rather than implied: discarding the result leaves
# the store exactly as it was, which is indistinguishable from a sweep that
# found nothing -- the same class of failure as GH-29's clean report.
check("discarding it leaves an inventory that never saw the host",
      parse.merge_inventory({}, {})[0], {})

# --- self-test: prove the checks above can actually fail --------------------
print("\nSELF-TEST (these MUST report a failure to prove the gate works)")
_p, _f = PASS, FAIL
check("deliberately wrong equality", 1, 2)
# Proves the AST walkers really discriminate: a method that does not scan must
# not be found to scan, and a synthetic unbound call must be caught.
_fake = ast.parse(
    "async def f():\n    await self.scanner.async_scan(['x'])\n"
).body[0]
check("the unbound-call detector finds a planted defect",
      bare_scan_calls(_fake), [])
detected = FAIL - _f
PASS, FAIL = _p, _f
if detected == 2:
    PASS += 1
    print("  PASS  self-test: both deliberate failures were detected")
else:
    FAIL += 1
    print(f"  FAIL  self-test: expected 2 detected failures, saw {detected}")

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
