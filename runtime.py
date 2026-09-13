"""Where a merged entry keeps its scan coordinator -- one door, deliberately.

WHY THIS FILE EXISTS. Merging three integrations under one
config entry and changed `entry.runtime_data` from a single coordinator into a
dict of three (const.py records the shape). Every platform dispatcher was
updated to index it. `scan/scan_service.py` was NOT, and kept a
`hasattr(entry.runtime_data, "async_run_custom_scan")` duck-type test -- which
a dict cannot satisfy, ever, for any configuration. Both scan services
therefore refused every call network-wide from the merge onward.

THE COST WAS PAID ON THE MESSAGE, NOT THE CALL. The refusal named a missing
prerequisite ("no network_inventory entry is set up to scan"), so it read as an
configuration gap rather than an accessor bug -- and it named a domain
that has not existed since the merge, which cannot be created and so cannot be
found missing. A reader went looking for the entry instead of at the lookup.
Hence the rule: a config key read by two code paths goes through ONE
accessor.

NOTHING HERE IMPORTS HOME ASSISTANT. The shape of runtime_data is this repo's
own decision, so the suite that judges it must run without a core release
underneath it -- the pure layer tests/requirements.txt describes.
"""

from __future__ import annotations

from typing import Any

# The key `__init__.py` writes. Named once so a rename cannot land on the
# writer and miss a reader, which is the shape of the bug above.
KEY_SCAN = "scan"
# The alert monitor (alerts.py), written beside the coordinators by the same
# line and read only through `alert_monitor_of`, for the same reason.
KEY_ALERTS = "alerts"


def scan_coordinator_of(entry: Any) -> Any | None:
    """The scan coordinator on one entry, or None if it has not got one.

    TOLERANT BY DESIGN, because its callers ask about entries they do not
    own: the service lookup sweeps every entry of this domain, and one that
    is mid-setup, failed setup, or unloaded carries no runtime_data at all.
    "Cannot scan" is the right answer there, not an exception -- and unlike
    the duck-type test it replaces, this one is wrong only when the key is
    genuinely absent.
    """
    data = getattr(entry, "runtime_data", None)
    if not isinstance(data, dict):
        return None
    return data.get(KEY_SCAN)


def alert_monitor_of(entry: Any) -> Any | None:
    """The alert monitor on one entry, or None if it has not got one."""
    data = getattr(entry, "runtime_data", None)
    if not isinstance(data, dict):
        return None
    return data.get(KEY_ALERTS)


def scan_coordinators(entries: Any) -> list[Any]:
    """Every entry's scan coordinator that can actually run a scan here.

    THE `hasattr` IS THE MODE DISCRIMINATOR AND IT IS KEPT ON PURPOSE.
    `LocalCoordinator` defines `async_run_custom_scan`; `AgentCoordinator`
    does not, because the remote agent exposes no custom-scan channel. So the
    structural signal is the method itself rather than a mode string read
    back off the entry -- discover, don't pin. The bug this fixed was
    never this test; it was the object the test was applied to.
    """
    found = []
    for entry in entries:
        coordinator = scan_coordinator_of(entry)
        if coordinator is not None and hasattr(coordinator, "async_run_custom_scan"):
            found.append(coordinator)
    return found
