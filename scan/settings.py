"""The scan SCOPE and SCHEDULE vocabulary: one accessor over the config entry.

WHY THIS FILE EXISTS. `scan/const.py`'s header states the rule -- "every
address, credential and interval is config-entry data rather than a constant"
-- and the schedule broke it in both directions. In local mode the two sweep
clocks and the SSH probe clock were module constants, so changing how often
the network is scanned meant editing this repo and restarting Home Assistant.
In agent mode they are `OnCalendar=` lines in systemd timer units on the
scanner host, which is worse: outside the config entry, outside this repo, and
invisible to the integration that reports on their results.

TARGETS AND SCHEDULE ARE READ THROUGH ONE FUNCTION, NEVER TWO PATHS.
`entry.data` holds what setup collected; `entry.options` holds what the options
flow has edited since. A config key read by two code paths can silently lose
state -- a form defaulting from `data` while the coordinator scans from
`options` would show the operator one subnet list and sweep another, and
neither would be visibly wrong. So the coordinator, the schedule switches and
the options form all call `resolve_settings` and nothing reads either mapping
for these keys directly.

THIS MODULE IMPORTS NOTHING FROM HOME ASSISTANT, deliberately, in the same way
`join.py` and `options.py` do not: what it decides is a pure function of two
mappings and is therefore testable without a running instance.

OUT-OF-RANGE STORED VALUES ARE CLAMPED, NOT REFUSED. The form validates on
submit and cannot store one; a value outside the bounds can only arrive from a
hand-edited `.storage` file or from bounds that moved in a later version. In
either case the tick has to keep running -- raising here would take the whole
coordinator down over a number, and a monitor that vanishes because its own
setting is odd is the failure the never-raise contract exists to refuse.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from .const import (
    CONF_DISCOVERY_INTERVAL,
    CONF_DISCOVERY_TIMEOUT,
    CONF_EXCLUDE,
    CONF_SERVICE_INTERVAL,
    CONF_SSH_INTERVAL,
    CONF_STALE_DAYS,
    CONF_TARGETS,
    DEFAULT_DISCOVERY_INTERVAL_MINUTES,
    DEFAULT_SERVICE_INTERVAL_MINUTES,
    DEFAULT_SSH_INTERVAL_MINUTES,
    DEFAULT_STALE_DAYS,
    MAX_DISCOVERY_INTERVAL_MINUTES,
    MAX_SERVICE_INTERVAL_MINUTES,
    MAX_SSH_INTERVAL_MINUTES,
    MAX_DISCOVERY_TIMEOUT_SECONDS,
    MIN_DISCOVERY_INTERVAL_MINUTES,
    MIN_DISCOVERY_TIMEOUT_SECONDS,
    MIN_SERVICE_INTERVAL_MINUTES,
    MIN_SSH_INTERVAL_MINUTES,
    MIN_STALE_DAYS,
)
from .coverage import derive_discovery_timeout


@dataclass(frozen=True, slots=True)
class ScanSettings:
    """What to sweep, and how often. Local mode only -- see `resolve_settings`."""

    targets: tuple[str, ...]
    exclude: tuple[str, ...]
    discovery_interval: timedelta
    service_interval: timedelta
    ssh_interval: timedelta
    # Seconds, not a timedelta: the scanner hands it straight to
    # `asyncio.wait_for`, and converting twice is how a unit gets lost.
    discovery_timeout: int


def split_list(value: str | list | None) -> list[str]:
    """Accept either a list or a comma-separated string.

    The forms collect targets as one text field because a repeating field is a
    poor fit for 'the two subnets I scan', but options set through YAML or an
    import may arrive as a real list. Handling both here means no caller has to
    know which it has. Moved from `scan/__init__.py`'s `_split` so the form and
    the coordinator cannot end up splitting the same string two ways.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return [part.strip() for part in str(value).split(",") if part.strip()]


def clamp_minutes(raw: Any, default: int, minimum: int, maximum: int) -> int:
    """A stored interval in minutes, forced inside its bounds."""
    try:
        minutes = int(raw)
    except (TypeError, ValueError):
        # Not a number at all. The default is the only honest answer: a zero
        # here would make the sweep due on every single tick.
        return default
    return max(minimum, min(maximum, minutes))


def _interval(
    data: Mapping[str, Any],
    options: Mapping[str, Any],
    key: str,
    default: int,
    minimum: int,
    maximum: int,
) -> timedelta:
    raw = options.get(key, data.get(key, default))
    return timedelta(minutes=clamp_minutes(raw, default, minimum, maximum))


def resolve_settings(
    data: Mapping[str, Any], options: Mapping[str, Any]
) -> ScanSettings:
    """Merge what setup collected with what the options flow has since edited.

    TARGETS AND EXCLUDE FALL BACK DIFFERENTLY, and the difference is load
    bearing. An empty target list is never a valid answer -- it would mean
    scanning nothing, which the forms refuse -- so an empty or absent option
    falls back to `data`. An empty EXCLUDE list is a perfectly ordinary answer:
    it means the operator removed the last exclusion, and falling back to
    `data` there would silently reinstate an address they had just decided to
    stop protecting. So exclude keys on PRESENCE, targets on emptiness.
    """
    targets = split_list(options.get(CONF_TARGETS)) or split_list(
        data.get(CONF_TARGETS)
    )
    if CONF_EXCLUDE in options:
        exclude = split_list(options.get(CONF_EXCLUDE))
    else:
        exclude = split_list(data.get(CONF_EXCLUDE))

    return ScanSettings(
        targets=tuple(targets),
        exclude=tuple(exclude),
        discovery_interval=_interval(
            data,
            options,
            CONF_DISCOVERY_INTERVAL,
            DEFAULT_DISCOVERY_INTERVAL_MINUTES,
            MIN_DISCOVERY_INTERVAL_MINUTES,
            MAX_DISCOVERY_INTERVAL_MINUTES,
        ),
        service_interval=_interval(
            data,
            options,
            CONF_SERVICE_INTERVAL,
            DEFAULT_SERVICE_INTERVAL_MINUTES,
            MIN_SERVICE_INTERVAL_MINUTES,
            MAX_SERVICE_INTERVAL_MINUTES,
        ),
        ssh_interval=_interval(
            data,
            options,
            CONF_SSH_INTERVAL,
            DEFAULT_SSH_INTERVAL_MINUTES,
            MIN_SSH_INTERVAL_MINUTES,
            MAX_SSH_INTERVAL_MINUTES,
        ),
        discovery_timeout=_discovery_timeout(data, options, targets),
    )


def _discovery_timeout(
    data: Mapping[str, Any], options: Mapping[str, Any], targets: list[str]
) -> int:
    """The liveness backstop: what was typed, or what the scope implies.

    ABSENT IS NOT "USE A DEFAULT", IT IS "DERIVE". There is no sensible flat
    number here -- the cost of a liveness sweep is a function of how much
    address space the operator asked for, and the flat 300s this replaced
    failed every sweep forever on a `/16` (GH-34). So an entry that has never
    touched the field gets a budget that tracks its own scope.

    A TYPED VALUE PINS IT, deliberately, and stops tracking scope. That is
    what setting it means, and the form says so on the field; an override that
    silently kept moving would not be an override.

    Clamped on read like every other key here, because a hand-edited
    `.storage` or bounds that moved between versions can both produce a value
    the form would now refuse -- and a timeout below what a sweep needs kills
    every sweep, which is the failure this whole key exists to end.
    """
    raw = options.get(CONF_DISCOVERY_TIMEOUT, data.get(CONF_DISCOVERY_TIMEOUT))
    if raw is None or raw == "":
        return derive_discovery_timeout(targets)
    try:
        seconds = int(raw)
    except (TypeError, ValueError):
        # Not a number at all, so it says nothing about how long to wait.
        # Deriving is the honest answer, not a constant nobody chose.
        return derive_discovery_timeout(targets)
    return max(
        MIN_DISCOVERY_TIMEOUT_SECONDS,
        min(MAX_DISCOVERY_TIMEOUT_SECONDS, seconds),
    )


def resolve_stale_days(data: Mapping[str, Any]) -> int:
    """How long a host may go unseen before its record is forgotten.

    READ FROM `data` ALONE, AND THAT IS NOT THE OVERSIGHT IT LOOKS LIKE. Every
    other key in this module has an options editor and is re-read per sweep;
    `stale_days` has a RECONFIGURE editor (`async_step_reconfigure_local`),
    which writes `entry.data` and reloads the entry, so setup reads the new
    value on the way back up. It is deliberately not in the options flow:
    `config_flow.py`'s header rule is that no key gets two editors, because the
    loser goes silently inert. If it ever gains an options field, this function
    is where the `entry.options` fallback belongs -- not a second `.get` at the
    call site (GH-29 read the pair of lines in `scan/__init__.py` as a bug for
    exactly this reason, and the missing thing was this explanation).

    A STORED NUMBER BELOW THE FLOOR RESOLVES TO THE DEFAULT, NOT TO THE FLOOR,
    which is the one place this departs from `clamp_minutes`. Saturating an
    out-of-range interval merely scans more often than asked; saturating this
    one DELETES. `stale_days=1` forgets every device switched off for a day,
    along with the `first_seen` date that cannot be recovered by scanning
    harder -- so a 0 that someone hand-wrote meaning "never prune" would be
    honoured by destroying the inventory. Negative is worse and is the reason
    this function exists at all: `parse.prune` puts the cutoff in the FUTURE,
    every host reads as stale, and one sweep erases the whole network's
    history. The form cannot produce either value; a hand-edited `.storage`
    file and bounds that moved between versions both can.

    NO CEILING, matching the form, which has `vol.Range(min=...)` and no `max`.
    Retention longer than a month is an ordinary preference and the only cost
    of an absurd value is disk.
    """
    raw = data.get(CONF_STALE_DAYS, DEFAULT_STALE_DAYS)
    try:
        days = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_STALE_DAYS
    if days < MIN_STALE_DAYS:
        return DEFAULT_STALE_DAYS
    return days
