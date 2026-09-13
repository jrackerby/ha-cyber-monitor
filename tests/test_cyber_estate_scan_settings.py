#!/usr/bin/env python3
"""Tests for cyber_estate's scan scope/schedule resolver.

THREE SILENT FAILURE MODES ARE COVERED HERE.

The first is a settings surface that does not change anything. Targets and the
sweep clocks became editable at runtime, and the whole point is that the
coordinator reads what the form wrote -- through ONE function, so the form's
defaults and the sweep's actual scope cannot disagree. A second parsing path
would show the operator one subnet list and scan another, and neither would
look wrong.

The second is the exclude list quietly coming back. Targets fall back to
`entry.data` when the stored option is empty, because scanning nothing is never
a valid answer; exclude must NOT, because "no exclusions" is an ordinary answer
and reinstating a removed one would scan an address somebody had just decided
to protect. The two keys therefore resolve by different rules, and a single
shared "or fall back" would be wrong for one of them in a way nothing reports.

The third is a form offering a field with no label behind it. An untranslated
step or key renders as a raw slug, which reads as a bug in the integration
rather than a missing string, so the flow's step ids and field names are JOINED
against strings.json rather than eyeballed.

THE SELF-TEST AT THE END PROVES THESE CHECKS CAN FAIL.

Run: python3 tests/test_cyber_estate_scan_settings.py
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
COMPONENT = os.path.join(HERE, "..")
PKG = os.path.join(COMPONENT, "scan")

# A REAL PACKAGE, not two orphan modules. settings.py imports its bounds from
# const.py rather than restating them, so loading it by bare file path raises
# on the relative import -- and a harness that worked around that by loading a
# copy of the constants would be testing numbers this repo does not use.
_pkg = types.ModuleType("ce_scan")
_pkg.__path__ = [PKG]
sys.modules["ce_scan"] = _pkg


def load(name, filename):
    spec = importlib.util.spec_from_file_location(
        f"ce_scan.{name}", os.path.join(PKG, filename)
    )
    mod = importlib.util.module_from_spec(spec)
    # REGISTER BEFORE EXEC -- dataclasses resolves a class's module through
    # sys.modules, and a module loaded by spec alone raises AttributeError on
    # the first @dataclass rather than anywhere near the real cause.
    sys.modules[f"ce_scan.{name}"] = mod
    spec.loader.exec_module(mod)
    return mod


const = load("const", "const.py")
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


T = const.CONF_TARGETS
X = const.CONF_EXCLUDE
D = const.CONF_DISCOVERY_INTERVAL
S = const.CONF_SERVICE_INTERVAL
P = const.CONF_SSH_INTERVAL


def minutes(td):
    return int(td.total_seconds() // 60)


# --- splitting -------------------------------------------------------------
print("split_list takes both shapes the entry can hold")
check("comma string", settings.split_list("a, b ,c"), ["a", "b", "c"])
check("real list", settings.split_list(["a ", "", "b"]), ["a", "b"])
check("None", settings.split_list(None), [])
check("empty string", settings.split_list(""), [])
check("trailing comma drops nothing real", settings.split_list("a,"), ["a"])

# --- defaults --------------------------------------------------------------
print("\nan entry with no options resolves to the shipped defaults")
base = settings.resolve_settings({T: "192.0.2.0/24"}, {})
check("targets from data", list(base.targets), ["192.0.2.0/24"])
check("exclude empty", list(base.exclude), [])
check("discovery default", minutes(base.discovery_interval),
      const.DEFAULT_DISCOVERY_INTERVAL_MINUTES)
check("service default", minutes(base.service_interval),
      const.DEFAULT_SERVICE_INTERVAL_MINUTES)
check("ssh default", minutes(base.ssh_interval),
      const.DEFAULT_SSH_INTERVAL_MINUTES)

# --- the options flow's edit actually lands --------------------------------
print("\nan options edit overrides what setup collected")
# The motivating case: LAN01 Management added to a live entry.
edited = settings.resolve_settings(
    {T: "192.0.2.0/24", X: "192.0.2.1"},
    {T: ["192.0.2.0/24", "198.51.100.0/24"], D: 15, S: 720, P: 1440},
)
check("targets come from options",
      list(edited.targets), ["192.0.2.0/24", "198.51.100.0/24"])
check("discovery interval is the edited one", minutes(edited.discovery_interval), 15)
check("service interval is the edited one", minutes(edited.service_interval), 720)
check("ssh interval is the edited one", minutes(edited.ssh_interval), 1440)
check("an untouched key still falls back to data",
      list(edited.exclude), ["192.0.2.1"])

print("\ntargets and exclude fall back by DIFFERENT rules, on purpose")
check("emptied targets fall back rather than scanning nothing",
      list(settings.resolve_settings({T: "10.0.0.0/24"}, {T: ""}).targets),
      ["10.0.0.0/24"])
check("emptied exclude STAYS empty rather than reinstating a removed address",
      list(settings.resolve_settings({T: "10.0.0.0/24", X: "10.0.0.5"},
                                     {X: ""}).exclude),
      [])
check("an exclude key absent from options still falls back",
      list(settings.resolve_settings({T: "10.0.0.0/24", X: "10.0.0.5"},
                                     {D: 60}).exclude),
      ["10.0.0.5"])

# --- clamping --------------------------------------------------------------
print("\na stored interval outside its bounds is clamped, never obeyed")
low = settings.resolve_settings({T: "10.0.0.0/24"}, {D: 1, S: 1, P: 1})
check("discovery clamps up to its floor", minutes(low.discovery_interval),
      const.MIN_DISCOVERY_INTERVAL_MINUTES)
check("service clamps up to its floor", minutes(low.service_interval),
      const.MIN_SERVICE_INTERVAL_MINUTES)
check("ssh clamps up to its floor", minutes(low.ssh_interval),
      const.MIN_SSH_INTERVAL_MINUTES)
high = settings.resolve_settings(
    {T: "10.0.0.0/24"}, {D: 10**9, S: 10**9, P: 10**9}
)
check("discovery clamps down to its ceiling", minutes(high.discovery_interval),
      const.MAX_DISCOVERY_INTERVAL_MINUTES)
check("service clamps down to its ceiling", minutes(high.service_interval),
      const.MAX_SERVICE_INTERVAL_MINUTES)
check("ssh clamps down to its ceiling", minutes(high.ssh_interval),
      const.MAX_SSH_INTERVAL_MINUTES)
# ZERO IS THE DANGEROUS ONE: it clamps to the floor rather than making the
# sweep due on every single tick.
check("zero does not mean 'always due'",
      minutes(settings.resolve_settings({T: "x"}, {D: 0}).discovery_interval),
      const.MIN_DISCOVERY_INTERVAL_MINUTES)
check("a non-number falls back to the default, not to zero",
      minutes(settings.resolve_settings({T: "x"}, {D: "hourly"}).discovery_interval),
      const.DEFAULT_DISCOVERY_INTERVAL_MINUTES)
check("None falls back to the default too",
      minutes(settings.resolve_settings({T: "x"}, {D: None}).discovery_interval),
      const.DEFAULT_DISCOVERY_INTERVAL_MINUTES)

print("\nthe bounds themselves are coherent")
for _name, _lo, _default, _hi in (
    ("discovery", const.MIN_DISCOVERY_INTERVAL_MINUTES,
     const.DEFAULT_DISCOVERY_INTERVAL_MINUTES,
     const.MAX_DISCOVERY_INTERVAL_MINUTES),
    ("service", const.MIN_SERVICE_INTERVAL_MINUTES,
     const.DEFAULT_SERVICE_INTERVAL_MINUTES,
     const.MAX_SERVICE_INTERVAL_MINUTES),
    ("ssh", const.MIN_SSH_INTERVAL_MINUTES,
     const.DEFAULT_SSH_INTERVAL_MINUTES,
     const.MAX_SSH_INTERVAL_MINUTES),
):
    check(f"{_name}: min <= default <= max", _lo <= _default <= _hi, True)
# A SWEEP CANNOT BE DUE MORE OFTEN THAN THE CLOCK THAT ASKS. An interval below
# LOCAL_TICK is a setting that lies about itself: it would be accepted, stored,
# displayed, and then behave as LOCAL_TICK.
check("the discovery floor is the coordinator's own tick",
      const.MIN_DISCOVERY_INTERVAL_MINUTES, minutes(const.LOCAL_TICK))

# --- the coordinator reads the resolver, not the old constants -------------
#
# Checked on the SOURCE rather than by importing: coordinator.py imports Home
# Assistant and this suite must not.
print("\nthe coordinator schedules off the resolver, not module constants")
_coord = open(os.path.join(PKG, "coordinator.py")).read()
for _dead in ("LOCAL_DISCOVERY_INTERVAL", "LOCAL_SERVICE_INTERVAL",
              "SSH_PROBE_INTERVAL"):
    check(f"{_dead} is gone from the coordinator", _dead in _coord, False)
    check(f"{_dead} is gone from const.py too",
          hasattr(const, _dead), False)
check("the due checks read the live settings",
      _coord.count("settings.discovery_interval")
      + _coord.count("settings.service_interval")
      + _coord.count("settings.ssh_interval") >= 4, True)
check("a changed scope forces a discovery sweep",
      "_scope_changed" in _coord, True)
# BOTH HALVES OF THE SCOPE. Removing an exclusion widens what gets scanned
# exactly as much as adding a target, and a stamp that recorded only the
# targets would leave that widening unmeasured until the next scheduled sweep.
check("the scope stamp covers exclude as well as targets",
      "frozenset(settings.targets), frozenset(settings.exclude)" in _coord, True)
# EVERY FULL SWEEP STAMPS IT. The scheduled discovery, the scheduled service
# scan and the Scan now button all cover the whole live scope; one that
# stamped the clock but not the scope would leave the next tick launching a
# second, identical sweep.
check("all three full sweeps stamp the scope",
      _coord.count("self._swept_scope = self._scope_of("), 3)

# --- every step and field the options flow shows has a string --------------
print("\noptions flow <-> strings.json must not drift")
_flow = open(os.path.join(COMPONENT, "config_flow.py")).read()
_strings = json.load(open(os.path.join(COMPONENT, "strings.json")))
_en = json.load(open(os.path.join(COMPONENT, "translations", "en.json")))

check("en.json is the same document as strings.json", _en, _strings)

# The options flow's own half of the file, so the CONFIG flow's step ids
# (user/local/agent/...) cannot be mistaken for options steps.
_opts_src = _flow[_flow.index("class CyberEstateOptionsFlow"):]
_steps = set(re.findall(r'step_id="([a-z_]+)"', _opts_src))
_menu = set(re.findall(r'"(scan_scope|schedule|acknowledged_macs|alerting)"[,\]]', _opts_src))
_declared = set(_strings["options"]["step"])

check("every step the flow renders has a strings.json entry",
      sorted(_steps - _declared), [])
check("strings.json declares no options step the flow cannot render",
      sorted(_declared - _steps), [])
check("the menu offers exactly the steps that exist",
      sorted(_menu),
      sorted(_declared - {"init"}))
# PINS THE SCRAPER. Both comparisons above are set differences, so a regex
# that matched nothing would pass them both.
check("the scraper actually found the steps",
      sorted(_steps),
      ["acknowledged_macs", "alerting", "init", "scan_scope", "schedule"])

# `alerting` is not listed: its fields are alerting.py's, not scan/const.py's,
# and tests/test_alerting.py joins that step against strings.json itself.
_expected_fields = {
    "scan_scope": {const.CONF_TARGETS, const.CONF_EXCLUDE},
    "schedule": {D, S, P},
    "acknowledged_macs": {const.CONF_ACKNOWLEDGED_MACS},
}
# The flow spells fields as CONF_ SYMBOLS, never as literals, so the join has
# to go through const.py to find out which key a symbol stands for -- which is
# also the only way this test can notice a symbol whose VALUE changed.
_symbol_for = {
    getattr(const, _n): _n for _n in dir(const) if _n.startswith("CONF_")
}
for _step, _fields in _expected_fields.items():
    _labelled = set(_strings["options"]["step"][_step].get("data", {}))
    check(f"{_step}: every field has a label", sorted(_fields - _labelled), [])
    check(f"{_step}: no label without a field", sorted(_labelled - _fields), [])
    # Scoped to THIS step's method body. Searching the whole class would let a
    # field belonging to another step satisfy the check.
    _start = _opts_src.index(f"async def async_step_{_step}")
    _rest = _opts_src[_start + 1:]
    _end = _rest.find("\n    async def ")
    _body = _rest if _end < 0 else _rest[:_end]
    for _field in _fields:
        check(f"{_step}: {_symbol_for[_field]} is really on that form",
              _symbol_for[_field] in _body, True)

check("invalid_target is an options error, not only a config one",
      "invalid_target" in _strings["options"]["error"], True)

# --- the merge that stops one step deleting another's keys ------------------
print("\nsaving one step must not wipe the others")
check("every save merges over the stored options",
      _opts_src.count("**self.config_entry.options"), 1)
check("no step returns a bare data= dict of its own keys",
      re.search(r"async_create_entry\(\s*data=\{[A-Z]", _opts_src) is None, True)

# --- self-test: prove the checks above can actually fail --------------------
print("\nSELF-TEST (these MUST report a failure to prove the gate works)")
_p, _f = PASS, FAIL
check("deliberately wrong equality", 1, 2)
check("deliberately wrong membership", "nope" in _coord, True)
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
