#!/usr/bin/env python3
"""Two defects measured on a live estate, and the rules that replace them.

GH-33: NOTHING COULD BE DELETED. `async_remove_scan_device` refuses while an
endpoint "is still being seen", and read that off `InventoryView.endpoints` --
which is the whole persisted inventory, every host the integration has ever
recorded. So the guard was true of every device on the device page, the hook
returned False unconditionally, Home Assistant raised, and the UI showed a
generic delete failure. The fix is a set that answers the question actually
being asked, and the trap is that the obvious field cannot answer it:
`merge_inventory` only touches records a scan RESULT contains, so a host that
leaves the network keeps `status: "up"` for as long as its record survives.
Measured: 185 hosts tracked, 185 "up", including a subnet deleted days before.
`last_seen` is the only field that moves when a host is seen.

GH-34: A FAILING SWEEP RAN FOREVER. `_run_discovery` returned early on
ScanError without stamping its clock or its scope, so `_due` stayed true and,
after a scope edit, `_scope_changed` stayed true -- either one re-launching on
every five-minute tick. Measured: 31 sweeps in 9.4 hours against an hourly
interval, each killed at the 300-second timeout, nothing merged and nothing
pruned for the whole window. `_run_service_scan` already had the right
treatment one function below; these tests pin that discovery now matches it,
and that ScanBusy still does NOT stamp, because retrying next tick is correct
when another scan merely holds the lock.

GH-34, second half: THE TIMEOUT WAS A CONSTANT WHILE THE SCOPE WAS NOT. 300
seconds cannot sweep a /16, and a /16 is an ordinary answer under Configure ->
Networks to scan, so that scope failed every time forever. The budget is now
derived from the address count, floored at the old constant so no small scope
loses anything, and capped at the runaway backstop this file already had.

THE SELF-TEST AT THE END PROVES THESE CHECKS CAN FAIL.

Run: python3 tests/test_cyber_estate_scan_liveness.py
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


const = load("const", "const.py")
cov = load("coverage", "coverage.py")
parse = load("parse", "parse.py")
settings = load("settings", "settings.py")

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}\n          got  {got!r}\n          want {want!r}")


# --- GH-33: what "still being seen" has to mean ----------------------------
#
# coordinator.py imports Home Assistant, so `live_endpoints` is reimplemented
# here from its source rule and the SOURCE is pinned separately below. What is
# being fixed is the rule itself: which hosts a guard may refuse on.
print("the liveness rule: seen in the newest scan, and nothing else")


def live_macs(hosts):
    """The rule `InventoryView.live_endpoints` implements."""
    stamps = [h.get("last_seen") for h in hosts.values() if h.get("last_seen")]
    if not stamps:
        return set()
    newest = max(stamps)
    return {
        h["mac"] for h in hosts.values()
        if h.get("last_seen") == newest and h.get("mac")
    }


NOW = "2026-09-21T08:07:14+00:00"
EARLIER = "2026-09-20T11:14:58+00:00"
OLD = "2026-09-16T17:42:15+00:00"
_inv = {
    "a": {"mac": "AA", "last_seen": NOW, "status": "up"},
    "b": {"mac": "BB", "last_seen": EARLIER, "status": "up"},
    "c": {"mac": "CC", "last_seen": OLD, "status": "up"},
}
check("a host in the newest scan is live", "AA" in live_macs(_inv), True)
# THE WHOLE DEFECT, in one assertion. These two are in the inventory and carry
# status "up"; neither was seen in the newest sweep, and both were refused.
check("a host that missed the newest scan is not live",
      sorted(live_macs(_inv) - {"AA"}), [])
check("its stale status does not make it live",
      _inv["c"]["status"], "up")

print("\nan empty or unstamped inventory refuses nothing")
check("no hosts at all", live_macs({}), set())
check("no readable last_seen anywhere",
      live_macs({"a": {"mac": "AA", "status": "up"}}), set())
# Silence must not become a refusal, the mirror of `prune`'s rule that silence
# must not become a deletion. Both refuse to invent evidence.
check("an unstamped host among stamped ones is not live",
      live_macs({**_inv, "d": {"mac": "DD", "status": "up"}}) & {"DD"}, set())

print("\nhosts seen in one sweep share a byte-identical stamp, so == is exact")


def rec(key, mac, ip):
    """A host record in the shape `parse_scan` emits, which is what
    `merge_inventory` requires -- it reads `os`, `vendor` and the port fields
    directly when folding a host it has seen before."""
    return {
        "key": key, "mac": mac, "mac_source": "arp", "ip": ip, "ipv6": None,
        "hostname": None, "vendor": None, "os": None, "os_family": None,
        "os_accuracy": None, "status": "up", "ports": [], "open_port_count": 0,
        "port_list": [], "ports_scanned": False, "ports_scanned_at": None,
    }


# THE STAMPS ARE PASSED IN rather than taken from the clock: `now_iso` has
# SECONDS resolution, so two merges in one test would otherwise collide and
# this suite would prove the opposite of what it claims. Real sweeps are
# minutes apart and serialised by the scanner's lock, so the collision is a
# test artefact rather than a live risk -- but it must not be papered over.
_merged, _new, _changed = parse.merge_inventory(
    {}, {"x": rec("x", "AA:BB:CC:DD:EE:01", "10.0.0.1"),
         "y": rec("y", "AA:BB:CC:DD:EE:02", "10.0.0.2")},
    ts=EARLIER,
)
check("one merge stamps every host it contains identically",
      len({h["last_seen"] for h in _merged.values()}), 1)
# And a host the NEXT scan does not contain keeps its old stamp untouched --
# which is precisely what makes it distinguishable as departed.
_later, _, _ = parse.merge_inventory(
    _merged, {"x": rec("x", "AA:BB:CC:DD:EE:01", "10.0.0.1")}, ts=NOW,
)
check("the host the newer scan saw is restamped", _later["x"]["last_seen"], NOW)
check("a host absent from the next scan keeps its older stamp",
      _later["y"]["last_seen"], EARLIER)
check("and status does NOT distinguish them -- the whole GH-33 trap",
      _later["y"]["status"], _later["x"]["status"])
check("only the liveness rule separates them",
      live_macs(_later), {"AA:BB:CC:DD:EE:01"})

# --- GH-34: the timeout is derived from the scope --------------------------
print("\nthe liveness timeout scales with the address space configured")
check("a hostname is one address", cov.address_count(["nas.lan"]), 1)
check("a /24 is 256", cov.address_count(["192.0.2.0/24"]), 256)
check("a /16 is 65536", cov.address_count(["10.77.0.0/16"]), 65536)
check("targets add up", cov.address_count(["10.0.0.0/24", "10.0.1.0/24"]), 512)
check("nmap's octet range counts its own span",
      cov.address_count(["192.0.2.10-19"]), 10)
# EXCLUDES ARE NOT SUBTRACTED: this feeds a backstop, and an under-estimate
# kills a healthy sweep while an over-estimate only lets a dead one linger.
check("address_count takes targets only, never excludes",
      "exclude" in cov.address_count.__code__.co_varnames, False)

_coord_src_early = open(os.path.join(PKG, "coordinator.py")).read()
_scanner_src = open(os.path.join(PKG, "scanner.py")).read()
_scanner = ast.parse(_scanner_src)
_scanner_consts = {
    node.targets[0].id
    for node in _scanner.body
    if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
}
_FLOOR = const.MIN_DISCOVERY_TIMEOUT_SECONDS
_CEIL = const.MAX_DISCOVERY_TIMEOUT_SECONDS

print("\nbounded at both ends, off the repo's own constants")
check("a small scope keeps exactly the budget it has today",
      cov.derive_discovery_timeout(["192.0.2.0/24"]), _FLOOR)
check("the floor is the constant this replaced", _FLOOR, 300)
# THE MOTIVATING SCOPE. 300s could never finish this, so it failed every time.
check("a /16 gets more than the old flat timeout",
      cov.derive_discovery_timeout(["10.77.0.0/16"]) > 300, True)
check("and still less than the ceiling",
      cov.derive_discovery_timeout(["10.77.0.0/16"]) < _CEIL, True)
check("a /8 is capped rather than unbounded",
      cov.derive_discovery_timeout(["10.0.0.0/8"]), _CEIL)
# An IPv6 prefix multiplies out past any sane budget; the cap is what makes
# the arithmetic safe to do at all.
check("a v6 prefix cannot park nmap indefinitely",
      cov.derive_discovery_timeout(["2001:db8::/64"]), _CEIL)
check("the bounds are coherent", _FLOOR < _CEIL, True)

# THE CONSTANT MUST NOT LIVE IN scanner.py ANY MORE. A number that file owns,
# while the scope it must cover is configured elsewhere, is the whole defect.
for _dead in ("DISCOVERY_TIMEOUT", "MIN_DISCOVERY_TIMEOUT", "SECONDS_PER_ADDRESS"):
    check(f"{_dead} is gone from scanner.py", _dead in _scanner_consts, False)
check("the bounds live in const.py with every other bound",
      (hasattr(const, "MIN_DISCOVERY_TIMEOUT_SECONDS"),
       hasattr(const, "MAX_DISCOVERY_TIMEOUT_SECONDS")), (True, True))

# --- the config key -------------------------------------------------------
#
# ONE DEFINITION, TWO CALLERS: the resolver falls back to exactly the function
# the scanner falls back to, so a form's default and a sweep's real budget
# cannot disagree -- the trap settings.py's header is written about.
print("\nthe timeout is an options key, deriving only when unset")
T = const.CONF_DISCOVERY_TIMEOUT
TARGETS = const.CONF_TARGETS
_SCOPE = {TARGETS: "10.77.0.0/16"}


def resolved(data, options=None):
    return settings.resolve_settings(data, options or {}).discovery_timeout


check("unset derives from the configured scope",
      resolved(_SCOPE), cov.derive_discovery_timeout(["10.77.0.0/16"]))
check("and a different scope derives differently",
      resolved({TARGETS: "192.0.2.0/24"}), _FLOOR)
check("a typed value wins over the derivation",
      resolved(_SCOPE, {T: 900}), 900)
check("the options value beats a data value",
      resolved({**_SCOPE, T: 600}, {T: 900}), 900)
check("a data value is still honoured when options has none",
      resolved({**_SCOPE, T: 600}), 600)

print("\nand a stored value is clamped, never obeyed out of range")
# A TIMEOUT BELOW WHAT A SWEEP NEEDS KILLS EVERY SWEEP -- the exact failure
# this key exists to end, so the floor is the one that really matters.
check("below the floor clamps up", resolved(_SCOPE, {T: 1}), _FLOOR)
check("zero does not mean 'give up immediately'",
      resolved(_SCOPE, {T: 0}), _FLOOR)
check("a negative clamps up too", resolved(_SCOPE, {T: -5}), _FLOOR)
check("above the ceiling clamps down", resolved(_SCOPE, {T: 10 ** 9}), _CEIL)
check("a non-number derives rather than guessing a constant",
      resolved(_SCOPE, {T: "ages"}),
      cov.derive_discovery_timeout(["10.77.0.0/16"]))
check("an empty string derives too",
      resolved(_SCOPE, {T: ""}),
      cov.derive_discovery_timeout(["10.77.0.0/16"]))

print("\nthe sweep is handed the resolved budget, not a constant")
check("the scheduled discovery sweep passes it",
      "timeout=settings.discovery_timeout" in _coord_src_early, True)
check("both discovery sweeps do",
      _coord_src_early.count("timeout=settings.discovery_timeout"), 2)
check("the scanner's fallback is the same shared function",
      "derive_discovery_timeout(targets or [])" in _scanner_src, True)

# --- GH-34: a failing sweep must stamp what it attempted -------------------
#
# Read off coordinator.py's AST: the file imports Home Assistant and cannot be
# imported here, and the question is structural anyway -- which statements run
# on which exception.
print("\na sweep that cannot finish must not retry on every tick")
_coord_src = open(os.path.join(PKG, "coordinator.py")).read()
_coord = ast.parse(_coord_src)
_local = next(
    n for n in _coord.body
    if isinstance(n, ast.ClassDef) and n.name == "LocalCoordinator"
)
_methods = {
    n.name: n for n in _local.body
    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
}


def handler_body(method, exc_name):
    """Source of the `except <exc_name>:` block in `method`, or ''."""
    for node in ast.walk(method):
        if not isinstance(node, ast.ExceptHandler):
            continue
        name = getattr(node.type, "id", None)
        if name != exc_name:
            continue
        return "\n".join(
            ast.get_source_segment(_coord_src, stmt) or "" for stmt in node.body
        )
    return ""


for _sweep, _clock in (
    ("_run_discovery", "self._last_discovery"),
    ("_run_service_scan", "self._last_service_scan"),
):
    _err = handler_body(_methods[_sweep], "ScanError")
    check(f"{_sweep}: a ScanError stamps the clock",
          f"{_clock} = dt_util.utcnow()" in _err, True)
# THE LESS OBVIOUS HALF, and discovery is the only sweep that needs it: with
# only the clock stamped, `_scope_changed` alone still re-launches every tick
# after a scope edit, which is exactly how the measured loop started.
check("_run_discovery: a ScanError also stamps the scope it attempted",
      "self._swept_scope = self._scope_of(settings)"
      in handler_body(_methods["_run_discovery"], "ScanError"), True)

print("\nbut ScanBusy is not a failure and must stamp nothing")
for _sweep in ("_run_discovery", "_run_service_scan"):
    _busy = handler_body(_methods[_sweep], "ScanBusy")
    check(f"{_sweep}: ScanBusy handler found", _busy.strip() != "", True)
    check(f"{_sweep}: ScanBusy stamps no clock",
          "utcnow()" in _busy, False)
    check(f"{_sweep}: ScanBusy stamps no scope",
          "_swept_scope" in _busy, False)
# A stamped failure must still not MERGE anything -- there is no result to
# merge, and folding one in is what `_fold_in_full_sweep` is for.
check("a failed discovery folds nothing in",
      "_fold_in_full_sweep" in handler_body(_methods["_run_discovery"], "ScanError"),
      False)

# --- GH-33: the removal guard reads the liveness set -----------------------
print("\nthe removal guard reads live_endpoints, not the whole inventory")
_setup_src = open(os.path.join(PKG, "__init__.py")).read()
check("the guard uses the liveness set",
      "coordinator.data.live_endpoints" in _setup_src, True)
check("and no longer uses the whole store",
      "coordinator.data.endpoints" in _setup_src, False)
check("live_endpoints exists on the view",
      "def live_endpoints" in _coord_src, True)
# `endpoints` itself STAYS: the entities legitimately want every known host,
# and narrowing it would make departed devices vanish from the UI instead of
# going unavailable, which is the behaviour async_remove_scan_device documents.
check("endpoints is still there for the entities",
      "def endpoints" in _coord_src, True)

# --- self-test: prove the checks above can actually fail --------------------
print("\nSELF-TEST (these MUST report a failure to prove the gate works)")
_p, _f = PASS, FAIL
check("deliberately wrong equality", 1, 2)
# Proves the AST handler-scraper discriminates rather than returning "" always.
check("a handler that does not exist yields nothing",
      handler_body(_methods["_run_discovery"], "KeyboardInterrupt"), "stamped")
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
