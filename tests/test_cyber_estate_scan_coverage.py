#!/usr/bin/env python3
"""Tests for what GH-29 was actually about: a scan that reports CLEAN about
address space that no longer exists, and a retention setting nobody could see
the shape of.

FOUR SILENT FAILURE MODES ARE COVERED HERE.

The first is the motivating one. A whole-estate re-addressing left this
scanner sweeping three deleted subnets for a day. It did not error -- it
reported clean, because nothing was there, and a clean report about address
space that is gone renders exactly like a quiet network. `scan/coverage.py`
attributes hosts back to the target whose range holds them, so a target that
answers nothing can be named; these tests fix the attribution, because an
off-by-one in a span would either report a live subnet as dead (an alarm
nobody can act on) or a dead one as live (the original failure, restored).

The second is a false alarm that would never stop. A target entirely inside
the exclude list is empty BY INSTRUCTION, and a hostname target names no fixed
range at all. Counting either as empty would raise a repair on every sweep
forever, which trains the operator to ignore the one that matters.

The third is a partial sweep being read as a measurement. nmap killed mid-run
still emits the hosts it finished, and the repo's standing rule is that the
ABSENCE of a host in such a scan means nothing. One timeout must not start a
streak toward announcing that the network has disappeared.

The fourth is `stale_days`. GH-29 read `scan/__init__.py`'s `entry.data` read
as a dead control; it is not -- the key is edited by RECONFIGURE, which writes
`entry.data` and reloads -- but the surrounding check was missing, and the
value was not clamped at all. A hand-edited negative puts `parse.prune`'s
cutoff in the FUTURE and one sweep erases every host's `first_seen`, which no
amount of rescanning recovers. So the resolver is fixed here, and so is the
rule that the key has exactly one editor.

THE SELF-TEST AT THE END PROVES THESE CHECKS CAN FAIL.

Run: python3 tests/test_cyber_estate_scan_coverage.py
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

# A REAL PACKAGE, not orphan modules -- coverage.py and settings.py both import
# their vocabulary from const.py by relative import, and a harness that loaded
# copies of those constants would be testing numbers this repo does not ship.
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
cov = load("coverage", "coverage.py")

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}\n          got  {got!r}\n          want {want!r}")


# --- what a target covers --------------------------------------------------
print("a target is reduced to the span of addresses it names")
check("a /24 spans 256 addresses",
      (lambda s: s.last - s.first + 1)(cov.address_span("192.0.2.0/24")), 256)
check("a bare address spans itself",
      (lambda s: (s.first, s.last))(cov.address_span("192.0.2.7")),
      (lambda s: (s.first, s.last))(cov.address_span("192.0.2.7/32")))
check("nmap's last-octet range is understood",
      (lambda s: s.last - s.first + 1)(cov.address_span("192.0.2.10-19")), 10)
check("a /16 does not have to be enumerated to be spanned",
      (lambda s: s.last - s.first + 1)(cov.address_span("10.77.0.0/16")), 65536)
check("a hostname names no fixed span", cov.address_span("nas.lan"), None)
check("an empty target names no span", cov.address_span(""), None)
check("a host bit set does not refuse the network (strict=False)",
      cov.address_span("192.0.2.37/24") == cov.address_span("192.0.2.0/24"), True)

print("\nv4 and v6 integers overlap completely, so the family is carried")
_v6 = cov.address_span("2001:db8::/32")
check("a v6 target does not hold a v4 address",
      _v6.holds(*cov.address_key("10.0.0.1")), False)
check("a v6 target holds its own addresses",
      _v6.holds(*cov.address_key("2001:db8::5")), True)
check("a v4 target does not hold a v6 address",
      cov.address_span("0.0.0.0/0").holds(*cov.address_key("2001:db8::5")), False)

# --- attribution -----------------------------------------------------------
print("\nhosts are attributed to the target whose range holds them")
_found = cov.coverage(
    ["192.0.2.0/24", "198.51.100.0/24"],
    [],
    ["192.0.2.5", "192.0.2.6", "198.51.100.9"],
)
check("each target gets its own hosts",
      {c.target: c.hosts for c in _found},
      {"192.0.2.0/24": 2, "198.51.100.0/24": 1})
check("nothing is unmeasurable here",
      [c.unmeasurable for c in _found], [None, None])

print("\none live subnet must not vouch for a dead one")
_found = cov.coverage(
    ["192.0.2.0/24", "198.51.100.0/24"], [], ["192.0.2.5"]
)
check("the empty target is empty", [c.empty for c in _found], [False, True])

print("\noverlapping targets are each answered on their own terms")
_found = cov.coverage(["10.0.0.0/8", "10.1.2.0/24"], [], ["10.1.2.3"])
check("a host counts under both ranges that contain it",
      [c.hosts for c in _found], [1, 1])

# --- what must NOT be called empty -----------------------------------------
print("\nwhat cannot be measured is reported unmeasurable, never empty")
_found = cov.coverage(["nas.lan"], [], [])
check("a hostname target is not counted",
      _found[0].unmeasurable, cov.UNMEASURABLE_HOSTNAME)
check("and is therefore never empty", _found[0].empty, False)

_found = cov.coverage(["192.0.2.0/24"], ["192.0.2.0/24"], [])
check("a target wholly inside the exclude list is empty by instruction",
      _found[0].unmeasurable, cov.UNMEASURABLE_EXCLUDED)
check("and is therefore never empty", _found[0].empty, False)

_found = cov.coverage(["192.0.2.0/24"], ["192.0.2.0/25", "192.0.2.128/25"], [])
check("two excludes that between them cover the target also count",
      _found[0].unmeasurable, cov.UNMEASURABLE_EXCLUDED)

_found = cov.coverage(["192.0.2.0/24"], ["192.0.2.0/25"], [])
check("a PARTLY excluded target is still measured",
      (_found[0].unmeasurable, _found[0].empty), (None, True))

_found = cov.coverage(["192.0.2.0/24"], ["198.51.100.0/24", "nas.lan"], [])
check("an unrelated exclude does not make a target unmeasurable",
      _found[0].unmeasurable, None)

# --- which addresses count -------------------------------------------------
print("\nonly a host that ANSWERED counts as an answer")
_hosts = {
    "a": {"ip": "192.0.2.5", "status": "up"},
    "b": {"ip": "192.0.2.6", "status": "down"},
    "c": {"ip": None, "ipv6": "2001:db8::1", "status": "up"},
}
check("down hosts are not addresses that answered",
      sorted(cov.host_addresses(_hosts)), ["192.0.2.5", "2001:db8::1"])
check("a subnet of nothing but down hosts is empty",
      cov.coverage(["192.0.2.0/24"], [], cov.host_addresses(
          {"b": {"ip": "192.0.2.6", "status": "down"}}))[0].empty, True)
check("an unparseable address is dropped rather than raising",
      cov.address_key("not-an-address"), None)

# --- the streak ------------------------------------------------------------
print("\none empty sweep is a Tuesday; a streak is a signal")
_targets = ["192.0.2.0/24", "198.51.100.0/24"]
_streaks: dict = {}
for _ in range(const.EMPTY_TARGET_SWEEPS):
    _streaks = cov.update_streaks(
        _streaks, cov.coverage(_targets, [], ["192.0.2.5"])
    )
check("the live target never enters the streak table",
      "192.0.2.0/24" in _streaks, False)
check("the empty target counted every sweep",
      _streaks["198.51.100.0/24"], const.EMPTY_TARGET_SWEEPS)
check("and is reported at the threshold",
      cov.unreachable(_streaks, const.EMPTY_TARGET_SWEEPS),
      ("198.51.100.0/24",))
check("one sweep short of the threshold reports nothing",
      cov.unreachable(_streaks, const.EMPTY_TARGET_SWEEPS + 1), ())

print("\na single answer resets the streak rather than decrementing it")
_reset = cov.update_streaks(
    _streaks, cov.coverage(_targets, [], ["192.0.2.5", "198.51.100.9"])
)
check("an answering target leaves the table entirely", _reset, {})
check("so the repair clears", cov.unreachable(_reset, 1), ())

print("\na target that leaves the configuration leaves the table")
_gone = cov.update_streaks(_streaks, cov.coverage(["192.0.2.0/24"], [], []))
check("only configured targets survive a sweep",
      sorted(_gone), ["192.0.2.0/24"])
check("and its count starts fresh, not from the old streak",
      _gone["192.0.2.0/24"], 1)

print("\nan unmeasurable target can never accumulate a streak")
_h: dict = {}
for _ in range(const.EMPTY_TARGET_SWEEPS + 2):
    _h = cov.update_streaks(_h, cov.coverage(["nas.lan"], [], []))
check("a hostname target never enters the table", _h, {})

print("\nthe reported list is stable between sweeps")
check("unreachable() sorts rather than reporting dict order",
      cov.unreachable({"b": 9, "a": 9, "c": 9}, 1), ("a", "b", "c"))

# --- the GH-29 scenario, end to end ----------------------------------------
print("\nthe estate that raised GH-29: 192.168.x deleted, 10.77/16 live")
_scope = ["192.168.101.0/24", "192.168.103.0/24", "192.168.106.0/24",
          "10.77.0.0/16"]
_live = ["10.77.1.4", "10.77.1.9", "10.77.20.31"]
_streaks = {}
for _sweep in range(const.EMPTY_TARGET_SWEEPS):
    _found = cov.coverage(_scope, [], _live)
    _streaks = cov.update_streaks(_streaks, _found)
check("the sweep is NOT empty overall, which is why a total cannot carry this",
      sum(c.hosts for c in _found), 3)
check("the three deleted subnets are named",
      cov.unreachable(_streaks, const.EMPTY_TARGET_SWEEPS),
      ("192.168.101.0/24", "192.168.103.0/24", "192.168.106.0/24"))
check("the live subnet is not named",
      "10.77.0.0/16" in cov.unreachable(_streaks, const.EMPTY_TARGET_SWEEPS),
      False)

# --- stale_days ------------------------------------------------------------
print("\nstale_days: the form's floor, and what a hand-edited file can hold")
check("absent resolves to the shipped default",
      settings.resolve_stale_days({}), const.DEFAULT_STALE_DAYS)
check("an ordinary value is obeyed",
      settings.resolve_stale_days({const.CONF_STALE_DAYS: 90}), 90)
check("the floor itself is obeyed",
      settings.resolve_stale_days({const.CONF_STALE_DAYS: const.MIN_STALE_DAYS}),
      const.MIN_STALE_DAYS)
check("a number stored as text is obeyed",
      settings.resolve_stale_days({const.CONF_STALE_DAYS: "45"}), 45)
check("there is no ceiling, because a long retention only costs disk",
      settings.resolve_stale_days({const.CONF_STALE_DAYS: 10 ** 6}), 10 ** 6)
# THE DESTRUCTIVE ONES. Saturating to the floor would forget every device
# switched off since yesterday, and `first_seen` does not come back.
check("zero resolves to the default, NOT to a one-day retention",
      settings.resolve_stale_days({const.CONF_STALE_DAYS: 0}),
      const.DEFAULT_STALE_DAYS)
check("a negative resolves to the default, not a cutoff in the future",
      settings.resolve_stale_days({const.CONF_STALE_DAYS: -5}),
      const.DEFAULT_STALE_DAYS)
check("a non-number resolves to the default rather than raising in setup",
      settings.resolve_stale_days({const.CONF_STALE_DAYS: "forever"}),
      const.DEFAULT_STALE_DAYS)
check("None resolves to the default too",
      settings.resolve_stale_days({const.CONF_STALE_DAYS: None}),
      const.DEFAULT_STALE_DAYS)

_setup = open(os.path.join(PKG, "__init__.py")).read()
check("setup reads stale_days through the resolver, not with a bare .get",
      "resolve_stale_days(entry.data)" in _setup, True)
check("and the old unclamped int() read is gone",
      "int(entry.data.get(CONF_STALE_DAYS" in _setup, False)

# --- one key, one editor ---------------------------------------------------
#
# Checked on the SOURCE rather than by importing: config_flow.py imports Home
# Assistant and voluptuous, and this suite must not.
print("\nstale_days has exactly ONE editor, and it is the one that reloads")
_flow = open(os.path.join(COMPONENT, "config_flow.py")).read()
_opts_src = _flow[_flow.index("class CyberEstateOptionsFlow"):]
_conf_src = _flow[:_flow.index("class CyberEstateOptionsFlow")]
check("the options flow does not offer stale_days",
      "CONF_STALE_DAYS" in _opts_src, False)
check("the reconfigure step does",
      "CONF_STALE_DAYS" in _conf_src, True)
# WHY THE PAIR ABOVE IS THE WHOLE POINT. `entry.data` is read once at setup, so
# an editor that did not reload would save successfully and change nothing --
# the "control that looks live and does nothing" this flow's header refuses.
_reconf = _conf_src[_conf_src.index("async def async_step_reconfigure_local"):]
_reconf = _reconf[:_reconf.index("async def async_step_reconfigure_agent")]
check("the step holding stale_days reloads the entry when it saves",
      "async_update_reload_and_abort" in _reconf, True)
check("stale_days is on that step's own form",
      "CONF_STALE_DAYS" in _reconf, True)

# --- the coordinator side --------------------------------------------------
print("\nthe coordinator measures coverage on every full scheduled sweep")
_coord = open(os.path.join(PKG, "coordinator.py")).read()
check("both scheduled sweeps record what they covered",
      _coord.count("self._record_coverage(settings, result)"), 2)
check("an incomplete sweep is not a measurement",
      "if not result.complete:" in _coord, True)
check("the streak table starts empty in each process",
      "self._empty_sweeps: dict[str, int] = {}" in _coord, True)
check("the repair is cleared when nothing is dead",
      "ir.async_delete_issue" in _coord, True)
check("and raised when something is",
      "ir.async_create_issue" in _coord, True)
# ONE ISSUE PER ENTRY, so a target removed from the scope cannot leave behind a
# repair about a subnet that is no longer scanned.
check("the issue id is per entry, not per target",
      'f"empty_targets_{config_entry_id}"' in _coord, True)
# THE REPAIR GOES WITH ITS SUBJECT. The issue registry is not cleared by
# removing a config entry, so a repair about targets nobody scans any more
# would sit there un-actionable and un-dismissable.
check("removing the entry clears its repair",
      "empty_targets_issue_id(entry.entry_id)" in _setup, True)
check("the threshold is the constant, never a literal",
      "EMPTY_TARGET_SWEEPS" in _coord, True)

# --- the repair has a string, with the placeholders it is given -------------
print("\nthe repair text <-> strings.json must not drift")
_strings = json.load(open(os.path.join(COMPONENT, "strings.json")))
_en = json.load(open(os.path.join(COMPONENT, "translations", "en.json")))
check("en.json is the same document as strings.json", _en, _strings)

_key = re.search(r'translation_key="([a-z_]+)"', _coord)
check("the coordinator names a translation key", bool(_key), True)
_issue = _strings.get("issues", {}).get(_key.group(1) if _key else "", {})
check("that key has a title", bool(_issue.get("title")), True)
check("that key has a description", bool(_issue.get("description")), True)

# A REPAIR RENDERS ITS PLACEHOLDERS RAW when one is missing, so the two sides
# are joined rather than eyeballed: an unfilled {targets} in front of an
# operator reads as a broken integration, not as a missing string.
_given = set(
    re.findall(
        r'"([a-z_]+)":',
        _coord[_coord.index("translation_placeholders={"):].split("}", 1)[0],
    )
)
_used = set(re.findall(r"\{([a-z_]+)\}", _issue.get("description", "")))
check("every placeholder the text uses is supplied", sorted(_used - _given), [])
check("every placeholder supplied is used", sorted(_given - _used), [])
check("the scraper actually found placeholders", sorted(_given),
      ["sweeps", "targets"])
# The fix belongs where the scope is actually editable, and the options flow is
# the only editor of it (see the config-flow header). A repair that sent the
# operator to Reconfigure would send them to the step that deliberately refuses
# to offer targets -- the dead end GH-29 walked into.
check("the description points at Configure, not Reconfigure",
      "Configure" in _issue.get("description", ""), True)

# --- the README's number is the code's number ------------------------------
#
# LAW 1: a claim carries the state it was true in. The README tells an operator
# how many empty sweeps it takes before the integration speaks up, and a
# threshold changed in const.py without the sentence changing would leave the
# documentation confidently wrong about the one number a reader acts on.
print("\nthe README states the threshold the code actually uses")
_readme = open(os.path.join(COMPONENT, "README.md")).read()
_words = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six"}
check("the README names the configured threshold in words",
      f"{_words.get(const.EMPTY_TARGET_SWEEPS, const.EMPTY_TARGET_SWEEPS)} "
      "consecutive full sweeps" in _readme, True)
check("and sends the reader to the editor that can fix it",
      "Configure → Networks to scan" in _readme, True)

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
