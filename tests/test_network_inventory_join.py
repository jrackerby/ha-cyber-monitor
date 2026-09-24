#!/usr/bin/env python3
"""Tests for scan/join.py (formerly the standalone network_inventory).

The join decides whether something on the network is accounted for. A wrong
answer is either a missed intruder or an alert that cries wolf until it is
muted, so the cases below include the ones that FAIL SILENTLY -- a mismatch in
MAC format does not throw, it just reports every host as unknown, which looks
exactly like a working alarm.

Run: python3 tools/test_network_inventory_join.py [path-to-inventory.json]
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# network_inventory merged into cyber_estate's scan/ subpackage.
MODULE = os.path.join(HERE, "..", "scan", "join.py")

spec = importlib.util.spec_from_file_location("network_inventory_join", MODULE)
join = importlib.util.module_from_spec(spec)
# REGISTER BEFORE EXEC. `dataclasses` resolves a class's module through
# sys.modules, so a module loaded by spec alone raises AttributeError on the
# first @dataclass rather than anywhere near the real cause.
sys.modules["network_inventory_join"] = join
spec.loader.exec_module(join)

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}\n          got  {got!r}\n          want {want!r}")


def host(mac=None, ip=None, status="up", ports=None, **kw):
    return {
        "mac": mac,
        "ip": ip,
        "status": status,
        "ports": ports or [],
        "port_list": [f"{p['proto']}/{p['port']}" for p in (ports or [])],
        **kw,
    }


print("\n--- normalise_mac ---")
n = join.normalise_mac
check("colon form", n("00:00:5e:00:53:23"), "00005e005323")
check("dash form", n("00-00-5E-00-53-23"), "00005e005323")
check("bare form", n("00005e005323"), "00005e005323")
check("dotted cisco form", n("0000.5e00.5323"), "00005e005323")
check("already lower", n("00:00:5e:00:53:23"), "00005e005323")
check("None", n(None), None)
check("empty", n(""), None)
# A short value must be REJECTED, not padded or accepted. Two malformed values
# that both normalised to something short would join against each other and
# manufacture a match that was never observed.
check("too short", n("00:00:5e"), None)
check("too long", n("00:00:5e:00:53:23:99"), None)
check("not hex", n("zz:zz:zz:zz:zz:zz"), None)

print("\n--- join_hosts: the three outcomes ---")
hosts = {
    "a": host(mac="AA:BB:CC:DD:EE:01", ip="10.0.0.1"),
    "b": host(mac="AA:BB:CC:DD:EE:02", ip="10.0.0.2"),
    "c": host(mac=None, ip="10.0.0.3"),
}
r = join.join_hosts(hosts, ["aa:bb:cc:dd:ee:01"])
check("matched", r.matched, 1)
check("unmatched", r.unknown_count, 1)
check("unjoinable (no MAC)", r.unjoinable, 1)
check("unmatched is the right host", r.unmatched[0]["ip"], "10.0.0.2")
check("checked excludes unjoinable", r.checked, 2)

print("\n--- the silent failure: format mismatch across the two sides ---")
# THE REGRESSION THIS FILE EXISTS FOR. Registry holds bare, scanner emits
# colons. Nothing throws; a broken join simply reports everything as unknown.
r = join.join_hosts(
    {"a": host(mac="AA:BB:CC:DD:EE:01", ip="10.0.0.1")},
    ["aabbccddee01"],
)
check("bare registry MAC matches colon scanner MAC", r.matched, 1)
check("  and reports zero unknown", r.unknown_count, 0)

r = join.join_hosts(
    {"a": host(mac="aabbccddee01", ip="10.0.0.1")},
    ["AA-BB-CC-DD-EE-01"],
)
check("dashed registry MAC matches bare scanner MAC", r.matched, 1)

print("\n--- a garbage MAC on the known side must not match anything ---")
r = join.join_hosts(
    {"a": host(mac="AA:BB:CC:DD:EE:01", ip="10.0.0.1")},
    ["not-a-mac", "", "00:00"],
)
check("no false match from unusable known MACs", r.matched, 0)
check("host reported unknown", r.unknown_count, 1)

print("\n--- acknowledgement is a third bucket, not a filter ---")
hosts = {
    "a": host(mac="AA:BB:CC:DD:EE:01", ip="10.0.0.1"),  # known
    "b": host(mac="AA:BB:CC:DD:EE:02", ip="10.0.0.2"),  # acknowledged
    "c": host(mac="AA:BB:CC:DD:EE:03", ip="10.0.0.3"),  # neither -- still unknown
}
r = join.join_hosts(hosts, ["aa:bb:cc:dd:ee:01"], ["aa:bb:cc:dd:ee:02"])
check("known MAC still reads matched", r.matched, 1)
check("acknowledged MAC is its own bucket", r.acknowledged_count, 1)
check("acknowledged host is the right one", r.acknowledged[0]["ip"], "10.0.0.2")
check("acknowledged host does NOT also count as unknown", r.unknown_count, 1)
check("the untouched host is the one still unknown", r.unmatched[0]["ip"], "10.0.0.3")
check("checked sums all three decided buckets", r.checked, 3)

print("\n--- a known MAC that is ALSO acknowledged reads matched, not acknowledged ---")
# Checked after the known-MAC match, never instead of it (see join_hosts'
# own docstring) -- a genuinely known host answering "does HA have a
# device for this" must not be relabelled by a stale acknowledgement entry.
r = join.join_hosts(
    {"a": host(mac="AA:BB:CC:DD:EE:01", ip="10.0.0.1")},
    ["aa:bb:cc:dd:ee:01"],
    ["aa:bb:cc:dd:ee:01"],
)
check("known wins over acknowledged", r.matched, 1)
check("not double-counted as acknowledged too", r.acknowledged_count, 0)

print("\n--- acknowledgement is format-tolerant, same as known_macs ---")
r = join.join_hosts(
    {"a": host(mac="aabbccddee02", ip="10.0.0.2")},
    [],
    ["AA-BB-CC-DD-EE-02"],
)
check("dashed acknowledgement matches bare scanner MAC", r.acknowledged_count, 1)

print("\n--- a garbage acknowledged MAC must not match anything ---")
r = join.join_hosts(
    {"a": host(mac="AA:BB:CC:DD:EE:01", ip="10.0.0.1")},
    [],
    ["not-a-mac", "", "00:00"],
)
check("no false acknowledgement from unusable acked MACs", r.acknowledged_count, 0)
check("host still reads unknown", r.unknown_count, 1)

print("\n--- rollups ---")
p = [{"proto": "tcp", "port": 22}, {"proto": "tcp", "port": 443}]
r = join.join_hosts(
    {
        "a": host(mac="AA:BB:CC:DD:EE:01", ip="10.0.0.1", ports=p),
        "b": host(mac="AA:BB:CC:DD:EE:02", ip="10.0.0.2", status="down"),
    },
    [],
)
check("hosts_up counts only up", r.hosts_up, 1)
check("exposed_services sums ports", r.exposed_services, 2)
check("hosts_with_port_data", r.hosts_with_port_data, 1)

print("\n--- liveness gate on unknown hosts ---")
# THIS FIXTURE ALREADY HAD A DOWN HOST AND ASSERTED NOTHING ABOUT IT.
# The whole behaviour -- "if the device isn't live on the network, it should
# not be shown as unknown" -- was covered only by join.py's own _self_test(),
# which nothing ran. So a
# regression that put offline hosts back in the unknown list passed CI in both
# repos. The rollup checks above cannot catch it: hosts_up, exposed_services
# and hosts_with_port_data are all identical whether or not host "b" is
# listed as unknown.
check("a host that is not up is NOT listed as unknown",
      [h["ip"] for h in r.unmatched], ["10.0.0.1"])
check("and the count agrees with the list", r.unknown_count, 1)

# The other half of the ruling, and the half a naive "filter everything by
# liveness" fix would break: an ACKNOWLEDGED host stays listed whether or not
# it answered this scan. An acknowledgement is a standing human
# decision about a device, never a live security read, and must never be
# silently subtracted.
r = join.join_hosts(
    {
        "a": host(mac="AA:BB:CC:DD:EE:01", ip="10.0.0.1", status="down"),
        "b": host(mac="AA:BB:CC:DD:EE:02", ip="10.0.0.2", status="down"),
    },
    [],
    ["AA:BB:CC:DD:EE:01"],
)
check("an acknowledged host stays listed while offline",
      [h["ip"] for h in r.acknowledged], ["10.0.0.1"])
check("acknowledged_count is not liveness-gated", r.acknowledged_count, 1)
check("the unacknowledged offline host is still dropped", r.unknown_count, 0)

print("\n--- ordering is deterministic ---")
many = {
    str(i): host(mac=f"AA:BB:CC:DD:EE:{i:02X}", ip=f"10.0.0.{i}")
    for i in range(9, 0, -1)
}
a = [h["ip"] for h in join.join_hosts(many, []).unmatched]
b = [h["ip"] for h in join.join_hosts(dict(reversed(list(many.items()))), []).unmatched]
check("same set, same order regardless of dict order", a, b)

print("\n--- SELF-TEST: these checks must be capable of failing ---")
r = join.join_hosts({"a": host(mac="AA:BB:CC:DD:EE:01", ip="10.0.0.1")}, [])
check("an unknown host is NOT reported as matched", r.matched, 0)
_before = FAIL
check("(deliberate failure, proving check() reports)", 1, 2)
if FAIL == _before:
    print("  BROKEN: check() did not report a known-bad comparison")
    sys.exit(2)
FAIL -= 1  # discount the deliberate one
PASS += 1
print("  PASS  check() reports a bad comparison")

# ---------------------------------------------------------------------------
# Real data, when a copy of a live inventory.json is handed in.
# ---------------------------------------------------------------------------
if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
    print(f"\n--- live inventory: {sys.argv[1]} ---")
    real = json.load(open(sys.argv[1]))
    r = join.join_hosts(real, [])
    total = r.matched + r.unknown_count + r.unjoinable
    check("every host is classified exactly once", total, len(real))
    print(f"        hosts={len(real)} up={r.hosts_up} "
          f"joinable={r.checked} no-mac={r.unjoinable} "
          f"services={r.exposed_services} with-ports={r.hosts_with_port_data}")
    # With no known MACs supplied, every joinable host must read unknown --
    # this is the control that proves the join is actually comparing.
    check("with an empty registry, all joinable hosts are unknown",
          r.unknown_count, r.checked)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
