"""Which of the configured targets a sweep actually found anything in.

WHY THIS FILE EXISTS. A sweep of address space that no longer exists reports
CLEAN. After a whole-estate re-addressing this scanner swept three deleted
subnets for a day and published zero unknown hosts and zero findings, which
rendered identically to a quiet network (GH-29). Nothing in the integration
could tell "swept and found nothing" from "swept nothing that exists", and a
security tool that reports clean about address space that is gone is worse than
no tool: it answers the question it was installed to answer, wrongly, with
confidence.

SO THE SIGNAL IS PER TARGET, NOT PER SWEEP. The sweep as a whole is almost
never empty -- one live subnet out of four hides the other three -- so a total
host count cannot carry this. Hosts are attributed back to the target whose
address range holds them, and a target that holds none of them is the thing
worth reporting.

ATTRIBUTION IS ARITHMETIC ON ADDRESSES, NOT ENUMERATION. A target is reduced to
the inclusive span of integers it names, and a host to one integer; /16s and
/8s are ordinary scan scopes here, so anything that walked the addresses would
cost megabytes to answer a question about emptiness. The same spans answer
"is this target entirely inside the exclude list", which has to be asked
because a fully-excluded target is empty by instruction and reporting it as
missing would be a false alarm every sweep, forever.

WHAT CANNOT BE MEASURED IS REPORTED AS UNMEASURABLE, NEVER AS EMPTY. A
hostname target names no fixed span -- resolving it is a network read this
module deliberately cannot do -- so it is excluded from the count rather than
counted as zero. `unmeasurable` is the same refusal `settings.py` and the
never-raise contract make elsewhere: say "unmeasured" and stop.

THIS MODULE IMPORTS NOTHING FROM HOME ASSISTANT, like `join.py`, `options.py`
and `settings.py`: what it decides is a pure function of a target list, an
exclude list and a set of observed addresses, and is therefore testable without
a running instance.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

# nmap's own last-octet range form, the second shape `options.validate_target`
# accepts. Restated here rather than imported because this module reads it to
# find a SPAN and that one reads it to refuse an argument; the two questions
# are different and a shared pattern would invite one to move for the other.
_OCTET_RANGE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3})")

# Why a target is not counted. Kept as text rather than a bool so the reason
# reaches the log and the diagnostics, where "not measured" without a reason is
# indistinguishable from a bug.
UNMEASURABLE_HOSTNAME = "names a host rather than an address range"
UNMEASURABLE_EXCLUDED = "entirely covered by the exclude list"


@dataclass(frozen=True, slots=True)
class Span:
    """The inclusive range of addresses one target names.

    `version` is carried because 4 and 6 integers overlap completely: without
    it `10.0.0.1` would be held by `::/0` and by any low IPv6 prefix, and a
    v6-only target would look populated by v4 hosts.
    """

    version: int
    first: int
    last: int

    def holds(self, version: int, value: int) -> bool:
        return version == self.version and self.first <= value <= self.last

    def within(self, others: Iterable["Span"]) -> bool:
        """Whether every address of this span is covered by `others`.

        Walks the covering spans in order and advances a cursor, so two
        adjacent excludes cover a target between them. An empty `others`
        covers nothing, which is the common case and the cheap one.
        """
        cursor = self.first
        for other in sorted(
            (o for o in others if o.version == self.version),
            key=lambda o: o.first,
        ):
            if other.first > cursor:
                # A gap before this one, so the target is not fully covered.
                return False
            if other.last >= self.last:
                return True
            cursor = max(cursor, other.last + 1)
        return False


def address_span(value: str) -> Span | None:
    """The span a target names, or None when it names no fixed span.

    Accepts exactly what `options.validate_target` accepts -- an address, a
    CIDR network, or nmap's last-octet range -- and returns None for the third
    form it allows, a hostname. None is NOT an error here: it is the honest
    answer to "which addresses does `nas.lan` cover", which needs a resolver.
    """
    text = (value or "").strip()
    if not text:
        return None

    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        pass
    else:
        return Span(net.version, int(net.network_address), int(net.broadcast_address))

    match = _OCTET_RANGE.fullmatch(text)
    if match:
        try:
            base = ipaddress.ip_address(match.group(1))
        except ValueError:
            return None
        last_octet = int(match.group(2))
        if last_octet > 255:
            return None
        end = ipaddress.ip_address((int(base) & ~0xFF) | last_octet)
        # SORTED, not refused, for a descending range. nmap itself rejects
        # `192.0.2.64-1`, so a scan that produced hosts to attribute cannot
        # have contained one; ordering the pair keeps this function total
        # instead of returning None for a case that cannot reach it.
        lo, hi = sorted((int(base), int(end)))
        return Span(base.version, lo, hi)

    return None


def address_key(value: str | None) -> tuple[int, int] | None:
    """One observed address as (version, integer), or None if unusable."""
    text = (value or "").strip()
    if not text:
        return None
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    return addr.version, int(addr)


@dataclass(frozen=True, slots=True)
class TargetCoverage:
    """What one configured target contributed to one sweep."""

    target: str
    hosts: int
    # None when the target was counted. Text when it was not, saying why.
    unmeasurable: str | None = None

    @property
    def empty(self) -> bool:
        """Measured, and nothing answered. An unmeasurable target is never
        empty -- it is unmeasured, which is a different fact."""
        return self.unmeasurable is None and self.hosts == 0


def host_addresses(hosts: Mapping[str, Mapping[str, object]]) -> list[str]:
    """Every address a sweep saw ANSWER, v4 and v6 alike.

    ONLY `status == "up"`. nmap's XML carries hosts it probed and found down
    once verbosity is raised, and counting those would make a dead subnet look
    populated by the very addresses that prove it is dead. `join.py` gates on
    the same field for the same reason.
    """
    out: list[str] = []
    for host in hosts.values():
        if host.get("status") != "up":
            continue
        for key in ("ip", "ipv6"):
            value = host.get(key)
            if value:
                out.append(str(value))
    return out


def coverage(
    targets: Iterable[str],
    exclude: Iterable[str],
    addresses: Iterable[str],
) -> tuple[TargetCoverage, ...]:
    """Attribute observed addresses back to the targets that name them.

    One host can be counted under two overlapping targets, deliberately: the
    question asked of each target is "did anything in YOUR range answer",
    and apportioning a host to only the first matching target would report the
    second as empty on account of an overlap the operator configured.
    """
    excl = [s for s in (address_span(t) for t in exclude) if s is not None]
    seen = [k for k in (address_key(a) for a in addresses) if k is not None]

    out: list[TargetCoverage] = []
    for target in targets:
        span = address_span(target)
        if span is None:
            out.append(TargetCoverage(target, 0, UNMEASURABLE_HOSTNAME))
            continue
        if span.within(excl):
            # EMPTY BY INSTRUCTION. Nothing was scanned in here, so nothing
            # answering says nothing about whether the range exists.
            out.append(TargetCoverage(target, 0, UNMEASURABLE_EXCLUDED))
            continue
        out.append(
            TargetCoverage(
                target, sum(1 for version, value in seen if span.holds(version, value))
            )
        )
    return tuple(out)


def update_streaks(
    previous: Mapping[str, int], found: Iterable[TargetCoverage]
) -> dict[str, int]:
    """Count CONSECUTIVE sweeps in which a target answered with nothing.

    Only empty targets are kept. A target that answered, one that cannot be
    measured, and one that has left the configuration all drop out, so the
    result is exactly the set of targets currently running a streak and the
    caller cannot read a stale zero as a fresh measurement.

    One sweep is never enough. A subnet whose hosts are all asleep at 04:00 is
    an ordinary Tuesday; the same subnet empty across every sweep for hours is
    the signal, which is why this returns a count rather than a verdict.
    """
    streaks: dict[str, int] = {}
    for item in found:
        if item.empty:
            streaks[item.target] = previous.get(item.target, 0) + 1
    return streaks


def unreachable(streaks: Mapping[str, int], threshold: int) -> tuple[str, ...]:
    """Targets empty for `threshold` consecutive sweeps.

    Sorted rather than left in dictionary order, so an unchanged condition
    reports the same string every sweep instead of rewriting itself in the UI
    whenever the streaks happen to be rebuilt in a different order.
    """
    return tuple(sorted(t for t, n in streaks.items() if n >= threshold))
