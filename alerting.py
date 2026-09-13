"""Debounce, hold and rate-limit for the integration's security flags. Pure.

THIS MODULE IMPORTS NOTHING FROM HOME ASSISTANT, on purpose. It decides when a
finding becomes an alert, when an alert is allowed to clear, and how often the
bus may hear about either. A wrong answer here is a defensive automation that
blocks a guest's phone on one flicker, or one that never fires because the
flag it watches is stuck behind a hold -- logic with that failure mode has to
run in a test without booting a core release underneath it, which is the same
rule `scan/join.py` was written under.

THREE MECHANISMS, THREE DIFFERENT QUESTIONS. Conflating them is the defect
this file exists to prevent, so each is its own class with its own clock:

  * `Debouncer` answers "is this finding real yet". A host that answers one
    hourly sweep and not the next is a phone walking past, and an alarm that
    fires on it cries wolf until somebody mutes it. A finding is CONFIRMED
    after N consecutive observations in which it was present, and CLEARED
    after M consecutive observations in which it was not. Both edges are
    counted in observations, not seconds: the sweep cadence is operator-set
    and a clock here would silently mean a different number of sweeps
    whenever the schedule changed.

  * `HeldFlag` answers "may the entity's state change right now". Once the
    flag flips it cannot flip again for `min_hold_seconds`, whatever the
    debouncer says -- that is the state rate-limit. A change that arrives
    inside the hold is not lost: it is applied at the first observation
    after the hold expires, if it is still wanted then, and the number of
    changes deferred this way is counted and published, never silently
    swallowed.

  * `EventRateLimiter` answers "may the bus hear this one". A sliding window
    per event type; anything over the cap is dropped, and every drop is
    counted per type so the entity can state how much it declined to say.

NOTHING IS SUPPRESSED SILENTLY. Every deferred flip and every dropped event
lands in a counter the entity publishes -- a declined signal is stated, never
merely absent, so an operator reading a quiet flag can tell "nothing found"
from "found, and not yet allowed to say so".

ON THE RISE DWELL. Household directive surfaces in this estate dwell only on
the fall and never on the rise, and that rule is right for them: a tornado
cell must show the moment it is known. It does not govern here. Cyber never
co-mingles with the physical roll-up, a network sweep is a periodic sample
rather than a push, and the cost of a false rise is a defensive action taken
against something that was never there. The rise dwell is therefore a
deliberate default, and `confirm_observations=1` turns it off for an operator
who would rather have the latency.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Hashable, Iterable, Mapping

# ---------------------------------------------------------------- policy
#
# OPTIONS KEYS, WITH THE UNIT IN THE KEY. These are stored as bare integers in
# entry.options, and a key named `hold` holding 5 cannot be told apart from
# one holding 300 by anything reading the entry later. Same rule as the sweep
# clocks in scan/const.py.
CONF_CONFIRM_OBSERVATIONS = "alert_confirm_observations"
CONF_CLEAR_OBSERVATIONS = "alert_clear_observations"
CONF_MIN_HOLD_MINUTES = "alert_min_hold_minutes"
CONF_MAX_EVENTS_PER_HOUR = "alert_max_events_per_hour"

DEFAULT_CONFIRM_OBSERVATIONS = 2
DEFAULT_CLEAR_OBSERVATIONS = 2
DEFAULT_MIN_HOLD_MINUTES = 5
DEFAULT_MAX_EVENTS_PER_HOUR = 12

# BOUNDS, ENFORCED TWICE -- the options form refuses out-of-range input and
# the resolver clamps whatever it is handed, because a stored value can also
# arrive from a hand-edited .storage file or from bounds that moved between
# versions. A confirm count of 0 would assert a finding that was never
# observed; a hold of a day would leave a real intruder unreported for a day.
MIN_OBSERVATIONS = 1
MAX_OBSERVATIONS = 24
MIN_HOLD_MINUTES = 0
MAX_HOLD_MINUTES = 240
MIN_EVENTS_PER_HOUR = 1
MAX_EVENTS_PER_HOUR = 600

EVENT_WINDOW_SECONDS = 3600.0


@dataclass(frozen=True, slots=True)
class AlertPolicy:
    """The four numbers every flag and the event stream run on."""

    confirm_observations: int = DEFAULT_CONFIRM_OBSERVATIONS
    clear_observations: int = DEFAULT_CLEAR_OBSERVATIONS
    min_hold_seconds: float = DEFAULT_MIN_HOLD_MINUTES * 60.0
    max_events_per_hour: int = DEFAULT_MAX_EVENTS_PER_HOUR

    def as_attributes(self) -> dict[str, Any]:
        """The policy as the entity states it, so a quiet flag can be read
        against the rule that is keeping it quiet."""
        return {
            "confirm_observations": self.confirm_observations,
            "clear_observations": self.clear_observations,
            "min_hold_seconds": int(self.min_hold_seconds),
            "max_events_per_hour": self.max_events_per_hour,
        }


def _clamped(value: Any, default: int, lo: int, hi: int) -> int:
    """An int within [lo, hi], or the default for anything unparseable.

    A string "3" from a hand-edited store counts; "three" does not, and falls
    to the default rather than raising -- the options form is the place to
    refuse input, and a resolver that raised would take the whole entry down
    over one bad key.
    """
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, number))


def resolve_policy(options: Mapping[str, Any] | None) -> AlertPolicy:
    """ONE accessor. The options form's defaults, the monitor's live values and
    the entity's published policy all come through here, so the form cannot
    show one number while the flag runs on another."""
    opts = options or {}
    return AlertPolicy(
        confirm_observations=_clamped(
            opts.get(CONF_CONFIRM_OBSERVATIONS),
            DEFAULT_CONFIRM_OBSERVATIONS,
            MIN_OBSERVATIONS,
            MAX_OBSERVATIONS,
        ),
        clear_observations=_clamped(
            opts.get(CONF_CLEAR_OBSERVATIONS),
            DEFAULT_CLEAR_OBSERVATIONS,
            MIN_OBSERVATIONS,
            MAX_OBSERVATIONS,
        ),
        min_hold_seconds=60.0
        * _clamped(
            opts.get(CONF_MIN_HOLD_MINUTES),
            DEFAULT_MIN_HOLD_MINUTES,
            MIN_HOLD_MINUTES,
            MAX_HOLD_MINUTES,
        ),
        max_events_per_hour=_clamped(
            opts.get(CONF_MAX_EVENTS_PER_HOUR),
            DEFAULT_MAX_EVENTS_PER_HOUR,
            MIN_EVENTS_PER_HOUR,
            MAX_EVENTS_PER_HOUR,
        ),
    )


# ------------------------------------------------------------- debouncer


@dataclass(slots=True)
class Transitions:
    """What one observation changed. Keys, so the caller can look up detail."""

    asserted: list[Hashable] = field(default_factory=list)
    cleared: list[Hashable] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.asserted or self.cleared)


class Debouncer:
    """Per-key membership debounce over consecutive observations.

    A key is CONFIRMED once it has been present in `confirm` consecutive
    observations, and stays confirmed until it has been absent from `clear`
    consecutive observations. A single absence resets the rise count and a
    single presence resets the fall count -- "consecutive" is the whole
    mechanism, so it is not approximated by a running total.

    THE POLICY IS READ AT EACH OBSERVATION, not captured at construction.
    An operator who lowers the confirm count wants the pending host confirmed
    on the next sweep, not after a reload; the counts carried between
    observations are the observation counts, and the thresholds they are
    compared against are whatever the policy says now.
    """

    def __init__(self) -> None:
        self._confirmed: set[Hashable] = set()
        # Consecutive presences for keys not yet confirmed.
        self._rising: dict[Hashable, int] = {}
        # Consecutive absences for confirmed keys.
        self._falling: dict[Hashable, int] = {}

    @property
    def confirmed(self) -> frozenset[Hashable]:
        return frozenset(self._confirmed)

    @property
    def pending(self) -> dict[Hashable, int]:
        """Keys seen but not yet confirmed, with how many times so far."""
        return dict(self._rising)

    @property
    def clearing(self) -> dict[Hashable, int]:
        """Confirmed keys currently absent, with how many misses so far."""
        return dict(self._falling)

    def observe(self, present: Iterable[Hashable], policy: AlertPolicy) -> Transitions:
        """Fold one observation in and report what crossed a threshold."""
        seen = set(present)
        out = Transitions()

        # Rising edge: keys present and not yet confirmed.
        for key in seen - self._confirmed:
            count = self._rising.get(key, 0) + 1
            if count >= policy.confirm_observations:
                self._rising.pop(key, None)
                self._confirmed.add(key)
                out.asserted.append(key)
            else:
                self._rising[key] = count
        # A pending key that went absent starts again from nothing.
        for key in list(self._rising):
            if key not in seen:
                del self._rising[key]

        # Falling edge: confirmed keys that are absent.
        for key in list(self._confirmed):
            if key in seen:
                self._falling.pop(key, None)
                continue
            count = self._falling.get(key, 0) + 1
            if count >= policy.clear_observations:
                # pop, not del: at clear=1 the key was never counted.
                self._falling.pop(key, None)
                self._confirmed.discard(key)
                out.cleared.append(key)
            else:
                self._falling[key] = count

        out.asserted.sort(key=repr)
        out.cleared.sort(key=repr)
        return out

    def forget(self, keys: Iterable[Hashable]) -> None:
        """Drop keys from every bucket without reporting a transition.

        For a key that stopped being a candidate for reasons other than
        absence -- an operator acknowledged the MAC -- where a `cleared`
        event would say the host left, and it did not.
        """
        for key in keys:
            self._confirmed.discard(key)
            self._rising.pop(key, None)
            self._falling.pop(key, None)


# ------------------------------------------------------------- held flag


class HeldFlag:
    """A boolean that may not change more often than the policy's hold.

    `propose(wanted, now)` returns the state the entity should publish. A
    change requested inside the hold is DEFERRED, not dropped: the next
    proposal after the hold expires applies whatever is wanted then. Deferred
    proposals are counted so the entity can say the flag is being held.

    THE FIRST PROPOSAL IS NEVER HELD. A hold measured from construction would
    leave a freshly started integration unable to report a finding it had
    already confirmed for up to `min_hold_seconds` -- and the number it
    published in the meantime would be the constructor's default, which is a
    value about nothing.
    """

    def __init__(self, initial: bool = False) -> None:
        self._state = initial
        self._changed_at: float | None = None
        self._deferred = 0
        self._held_until: float | None = None

    @property
    def state(self) -> bool:
        return self._state

    @property
    def deferred(self) -> int:
        """Proposals refused by the hold since construction."""
        return self._deferred

    @property
    def held_until(self) -> float | None:
        """When the current hold ends, or None if the flag is free to change.

        None once the hold has expired, so a surface never prints a deadline
        that has already passed as though it were still coming.
        """
        return self._held_until

    def propose(self, wanted: bool, now: float, policy: AlertPolicy) -> bool:
        if self._held_until is not None and now >= self._held_until:
            self._held_until = None
        if wanted == self._state:
            return self._state
        if self._held_until is not None and now < self._held_until:
            self._deferred += 1
            return self._state
        self._state = wanted
        self._changed_at = now
        self._held_until = (
            now + policy.min_hold_seconds if policy.min_hold_seconds > 0 else None
        )
        return self._state


# ------------------------------------------------------- rate limiter


class EventRateLimiter:
    """At most N events per sliding hour, PER TYPE.

    Per type rather than one shared budget: a chatty `unknown_host_cleared`
    stream must not spend the budget a `vulnerability_actionable` needs.
    """

    def __init__(self, window_seconds: float = EVENT_WINDOW_SECONDS) -> None:
        self._window = window_seconds
        self._sent: dict[str, deque[float]] = {}
        self._suppressed: dict[str, int] = {}

    def allow(self, kind: str, now: float, policy: AlertPolicy) -> bool:
        """True if an event of `kind` may be fired now; records it if so."""
        sent = self._sent.setdefault(kind, deque())
        horizon = now - self._window
        while sent and sent[0] <= horizon:
            sent.popleft()
        if len(sent) >= policy.max_events_per_hour:
            self._suppressed[kind] = self._suppressed.get(kind, 0) + 1
            return False
        sent.append(now)
        return True

    @property
    def suppressed(self) -> dict[str, int]:
        """Dropped events since construction, per type. Empty means none."""
        return dict(self._suppressed)

    def sent_in_window(self, kind: str, now: float) -> int:
        sent = self._sent.get(kind)
        if not sent:
            return 0
        horizon = now - self._window
        return sum(1 for t in sent if t > horizon)
