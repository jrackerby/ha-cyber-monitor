#!/usr/bin/env python3
"""The per-endpoint deep-scan button, and the three ways it could lie (GH-36).

A button that runs a deep scan of ONE host belongs on that host's device page,
because that is where the question "what is actually open on this box" gets
asked. The machinery already existed -- `async_run_custom_scan`, the `deep`
profile, `EndpointEntity` -- so what is new is a control surface, and a control
surface is exactly the thing this repository keeps having to write comments
about. Three failures are possible and all three are silent:

AGENT MODE. `async_run_custom_scan` is a `LocalCoordinator` method. The agent's
v1 API has no custom-scan channel, which is why `custom_scan` and `scan_device`
both refuse there. A button offered on an agent entry would raise
AttributeError on press -- a control that looks live and does nothing, the
failure `button_entities.py`'s own header is written about. It must be ABSENT
in agent mode, not present and broken.

THE PROFILE DRIFTING. If this button named its own option list, it and the
scanner's own Scan now (deep) would gradually come to mean different things
while both saying "deep". It reads `options.PROFILES["deep"]`, and this suite
pins that it does.

PRUNING. An on-demand scan never ages the inventory (GH-31): aiming a scan at
one host must not start deleting every other record. `async_run_custom_scan`
is the path that already refuses to prune, which is another reason this button
goes through it rather than reaching for the store itself.

Plus the ordinary one: an endpoint with no current address cannot be scanned,
and scanning its LAST KNOWN address would scan whatever holds that address
now -- a different machine.

THE SELF-TEST AT THE END PROVES THESE CHECKS CAN FAIL.

Run: python3 tests/test_cyber_estate_scan_buttons.py
"""

from __future__ import annotations

import ast
import importlib.util
import json
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


options = load("options", "options.py")

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}\n          got  {got!r}\n          want {want!r}")


# button_entities.py imports Home Assistant, so it is PARSED, never imported.
_SRC = open(os.path.join(PKG, "button_entities.py")).read()
_TREE = ast.parse(_SRC)
_CLASSES = {n.name: n for n in _TREE.body if isinstance(n, ast.ClassDef)}
_FUNCS = {n.name: n for n in _TREE.body if isinstance(n, ast.FunctionDef)}


def dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def calls_in(node):
    return {
        name
        for n in ast.walk(node)
        if isinstance(n, ast.Call) and (name := dotted(n.func))
    }


def method(cls, name):
    """The named method of `cls`, or None -- including when `cls` is absent.

    TOLERANT ON PURPOSE. Every check below is written to REPORT a failure;
    a KeyError here would abort the run with a traceback instead, which says
    the suite is broken rather than that the code is.
    """
    for n in _CLASSES.get(cls, ast.ClassDef(body=[])).body:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    return None


print("the scraper found what this suite is about")
check("both button classes exist", sorted(_CLASSES), ["DeepScanButton", "ScanButton"])
check("the endpoint button is bound to an endpoint device",
      [b.id for b in _CLASSES.get("DeepScanButton", ast.ClassDef(bases=[])).bases],
      ["EndpointEntity", "ButtonEntity"])
_press = method("DeepScanButton", "async_press")
check("and it has a press handler", _press is not None, True)
if _press is None:
    # NOTHING BELOW CAN MEAN ANYTHING without it, and a run that continued
    # would report a wall of failures that all say the same thing once.
    print(f"\n{PASS} passed, {FAIL} failed (the button is absent; "
          "every later check needs it)")
    sys.exit(1)

# --- the profile is shared, not restated -----------------------------------
print("\nthe button runs the SAME deep profile as the scanner's own button")
check("the deep profile is what it says it is",
      sorted(options.PROFILES["deep"]),
      ["all_ports", "default_scripts", "service_versions"])
_press_src = ast.get_source_segment(_SRC, _press)
check("it reads the profile table rather than listing options itself",
      'OPTION_PROFILES["deep"]' in _press_src, True)
for _literal in ("all_ports", "default_scripts", "service_versions"):
    check(f"{_literal} is not restated in the button",
          _literal in _press_src, False)

# --- the path that does not prune ------------------------------------------
print("\nit goes through the on-demand path, which never ages the inventory")
check("the press runs a custom scan",
      "self.coordinator.async_run_custom_scan" in calls_in(_press), True)
# REACHING PAST IT WOULD BE THE BUG. `async_run_custom_scan` is what passes
# `stale_days=None`; a button that called `store.apply_scan` itself could
# prune on a scan aimed at one host.
check("and never touches the store directly",
      any(c.startswith("self.store") or c.startswith("self.coordinator.store")
          for c in calls_in(_press)), False)
check("nor drives the scanner directly, bypassing the merge",
      "self.coordinator.scanner.async_scan" in calls_in(_press), False)

# --- agent mode is refused by ABSENCE --------------------------------------
print("\nin agent mode the button is not offered at all")
_setup = _FUNCS["setup_scan_buttons"]
_setup_src = ast.get_source_segment(_SRC, _setup)
check("setup gates on the mode", "CONF_MODE" in _setup_src, True)
check("and returns early rather than building endpoint buttons",
      "!= MODE_LOCAL" in _setup_src, True)
# THE GATE MUST COME BEFORE THE ENDPOINT BUTTONS AND AFTER THE PROFILE ONES:
# the scanner's own Scan now buttons work in BOTH modes and must not be lost.
check("the profile buttons are added before the gate",
      _setup_src.index("ScanButton(") < _setup_src.index("MODE_LOCAL"), True)
check("the endpoint buttons are added after it",
      _setup_src.index("MODE_LOCAL") < _setup_src.index("DeepScanButton("), True)

# --- no address, no scan ---------------------------------------------------
print("\nan endpoint with no current address is refused, not aimed at random")
check("the press reads the host's current ip", '.get("ip")' in _press_src, True)
# ON THE AST, not on the text: `async_run_custom_scan` is named in the
# docstring too, so splitting the source on it puts the guard on the wrong
# side and the check passes for the wrong reason.
_guard = next(
    (n for n in _press.body
     if isinstance(n, ast.If)
     and any(isinstance(b, ast.Raise) for b in n.body)),
    None,
)
_scan_try = next((n for n in _press.body if isinstance(n, ast.Try)), None)
check("there is a guard that raises before any scan runs",
      _guard is not None and _scan_try is not None
      and _press.body.index(_guard) < _press.body.index(_scan_try), True)
check("and what it raises is a HomeAssistantError",
      dotted(next(b for b in _guard.body if isinstance(b, ast.Raise)).exc.func),
      "HomeAssistantError")
# SCANNING THE LAST KNOWN ADDRESS WOULD SCAN A DIFFERENT MACHINE, since a
# released lease is reissued. The target has to come from the live record.
check("the target is the address just read, not a stored attribute",
      "targets=[address]" in _press_src, True)

# --- failures reach the user ----------------------------------------------
print("\nevery way a scan can refuse is surfaced, never swallowed")
check("the press catches the shared error tuple",
      "SCAN_REQUEST_ERRORS" in _press_src, True)
check("and re-raises as HomeAssistantError",
      _press_src.count("HomeAssistantError"), 2)
# ScanBusy subclasses ScanError, so the tuple already covers "a scan is
# running"; a deep scan without the NSE tree refuses before the lock with a
# message naming the datadir, and that reason IS the value of the failure.
check("ScanError is in the tuple the module shares with ScanButton",
      "ScanError" in _SRC.split("SCAN_REQUEST_ERRORS = ")[1].split("\n")[0], True)
check("there is no bare except swallowing it",
      any(
          isinstance(h.type, type(None)) or h.type is None
          for n in ast.walk(_press)
          if isinstance(n, ast.Try)
          for h in n.handlers
      ), False)

# --- endpoints are discovered, and never duplicated ------------------------
print("\nendpoints gain the button as they appear, exactly once")
check("new endpoints are picked up on every refresh",
      "coordinator.async_add_listener" in _setup_src, True)
check("the listener is unregistered with the entry",
      "entry.async_on_unload" in _setup_src, True)
# NEVER PRUNED, like entities.py's own `seen`: a host that leaves keeps its
# button reading unavailable, and must not get a second one on its return.
check("a seen-set stops a returning host getting a second button",
      "seen.update" in _setup_src and "not in seen" in _setup_src, True)

# --- the string exists -----------------------------------------------------
print("\nthe button has a name, in both documents")
_strings = json.load(open(os.path.join(COMPONENT, "strings.json")))
_en = json.load(open(os.path.join(COMPONENT, "translations", "en.json")))
check("en.json is the same document as strings.json", _en, _strings)
_keys = set(_strings["entity"]["button"])
_declared = set(
    m.group(1)
    for m in __import__("re").finditer(r'translation_key="([a-z_]+)"', _SRC)
)
check("every button translation_key has a string",
      sorted(_declared - _keys), [])
check("and no string names a button that does not exist",
      sorted(_keys - _declared - {f"scan_{p}" for p in options.PROFILES}), [])
check("the scraper found the keys", "deep_scan" in _declared, True)

# --- the header no longer claims nothing waits -----------------------------
#
# It said "Nothing here waits for it", which was already untrue of the local
# standard and deep buttons and is untrue of this one. A comment that has
# expired is edited out, not argued with (LAW 1).
print("\nthe module says what it actually does about waiting")
_header = _SRC.split('"""')[1]
check("the header no longer claims nothing waits",
      "Nothing\nhere waits for it" in _header, False)
check("and states the local-mode behaviour instead",
      "AWAITS THE SCAN" in _header, True)

# --- self-test: prove the checks above can actually fail --------------------
print("\nSELF-TEST (these MUST report a failure to prove the gate works)")
_p, _f = PASS, FAIL
check("deliberately wrong equality", 1, 2)
check("the call scraper does not invent calls",
      "self.coordinator.nonexistent" in calls_in(_press), True)
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
