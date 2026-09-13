"""The alert monitor: turns findings into debounced flags and rate-limited events.

ONE OBJECT PER ENTRY, OWNED BY THE ENTRY, NOT BY AN ENTITY. It lives in
`entry.runtime_data` beside the three coordinators and listens to two of them
directly. Had the binary sensors owned the debouncers, disabling an entity in
the UI would have silently stopped the bus events too -- an automation that
had never touched the entity would go quiet with nothing in any log to say
why. Here the events fire whether or not anything is displayed, and the
entities are a read-only view of state the monitor holds.

WHAT IT WATCHES.

  * scan: the MACs in `InventoryView.unmatched` -- hosts that are up, carry
    a MAC, are known to no other integration and have not been acknowledged.
    Each MAC is a key in the debouncer, so one host confirming does not reset
    another's count. A MAC an operator acknowledges is FORGOTTEN rather than
    cleared: a `cleared` event says the host left the network, and it did not.

  * cve: the `actionable` count. ONE key, because the finding is "there is
    something to act on"; the affected list rides on the event and the entity
    as detail. `None` -- the coordinator could not read NVD -- is NOT
    observed at all: "ok at zero" and "could not read" are different values,
    and folding an unread into an absence would clear a real finding on an
    outage.

AN OBSERVATION IS A NEW SCAN, NOT A COORDINATOR PUBLISH. Measured on the
first deploy: the local coordinator republishes the same inventory on every
five-minute tick and after every sweep, so 46 hosts were "confirmed" eight
seconds after boot on two publishes of one scan. Each observation is keyed
on the inventory's own stamp -- `generated_at` for scan, `generated` for
cve -- and a publish carrying the stamp already observed moves the held flag
and the acknowledgement set but never the debounce counts.

CONFIRMED FINDINGS SURVIVE A RESTART. The confirmed keys and the last
observed stamp are persisted per entry; on start they are seeded silently, so
a restart fires no `detected` event for a host that was already known and the
flag comes up on without a burst. Measured on the same deploy: without this,
every boot re-fired the limit's worth of events and dropped the rest.

THE CLOCK IS WALL TIME, from `dt_util.utcnow()`, so a hold deadline can be
published as a timestamp an operator can read. A deferred flip is
re-proposed by a timer at the hold's expiry rather than waiting for the next
coordinator tick, otherwise a five-minute hold would cost up to ten.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.helpers.event import async_call_later
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util

from .alerting import (
    AlertPolicy,
    Debouncer,
    EventRateLimiter,
    HeldFlag,
    Transitions,
    resolve_policy,
)
from .const import DOMAIN
from .cve import cpe
from .scan.join import normalise_mac

_LOGGER = logging.getLogger(__name__)

EVENT_TYPE = f"{DOMAIN}_event"

KIND_UNKNOWN_HOST_DETECTED = "unknown_host_detected"
KIND_UNKNOWN_HOST_CLEARED = "unknown_host_cleared"
KIND_VULNERABILITY_ACTIONABLE = "vulnerability_actionable"
KIND_VULNERABILITY_CLEARED = "vulnerability_cleared"

FLAG_UNKNOWN_HOSTS = "unknown_hosts"
FLAG_VULNERABILITIES = "vulnerabilities"

# Detail caps, matching what the count sensors publish so an automation reading
# the flag and one reading the count see the same rows.
MAX_DETAIL = 25
_CVE_KEY = "actionable"

STORAGE_VERSION = 1
# Seconds to collapse a burst of transitions into one write.
SAVE_DELAY = 10


def _storage_key(entry_id: str) -> str:
    return f"{DOMAIN}.alerts.{entry_id}"


async def async_remove_alert_store(hass: HomeAssistant, entry_id: str) -> None:
    """Forget the persisted confirmed set when the ENTRY is removed."""
    await Store(hass, STORAGE_VERSION, _storage_key(entry_id)).async_remove()


class _Flag:
    """One debounced, held flag and the keys behind it."""

    def __init__(self) -> None:
        self.debouncer = Debouncer()
        self.held = HeldFlag()
        # Last-known detail per key, so a `cleared` event can still name the
        # host that left -- the inventory view no longer lists it.
        self.detail: dict[Any, dict[str, Any]] = {}
        self.wanted = False
        self.last_observed: str | None = None
        # The inventory stamp of the last observation counted. A publish
        # carrying the same stamp is the same scan and is not counted again.
        self.stamp: Any = None


class AlertMonitor:
    """Debounces two coordinators' findings and fires the bus events."""

    def __init__(self, hass: HomeAssistant, entry, scan_coordinator, cve_coordinator) -> None:
        self.hass = hass
        self.entry = entry
        self._scan = scan_coordinator
        self._cve = cve_coordinator
        self._flags = {FLAG_UNKNOWN_HOSTS: _Flag(), FLAG_VULNERABILITIES: _Flag()}
        self._limiter = EventRateLimiter()
        self._listeners: list[CALLBACK_TYPE] = []
        self._unsub: list[CALLBACK_TYPE] = []
        self._retry_timers: dict[str, CALLBACK_TYPE] = {}
        self._store: Store = Store(hass, STORAGE_VERSION, _storage_key(entry.entry_id))

    # -- lifecycle -----------------------------------------------------------

    async def async_start(self) -> None:
        """Restore what was confirmed, subscribe, and fold in what is held now.

        Called from `async_setup_entry` BEFORE the platforms are forwarded,
        so the monitor's listener runs ahead of every entity's on each
        refresh -- the entity then reads a state the monitor has already
        updated, never the previous tick's.
        """
        saved = await self._store.async_load() or {}
        for name, flag in self._flags.items():
            row = saved.get(name) or {}
            flag.debouncer.seed(row.get("confirmed") or [])
            flag.stamp = row.get("stamp")
            for key, detail in (row.get("detail") or {}).items():
                flag.detail[key] = detail
        self._unsub.append(self._scan.async_add_listener(self._on_scan))
        self._unsub.append(self._cve.async_add_listener(self._on_cve))
        self._on_scan()
        self._on_cve()

    async def async_stop(self) -> None:
        for unsub in self._unsub:
            unsub()
        self._unsub.clear()
        for cancel in self._retry_timers.values():
            cancel()
        self._retry_timers.clear()
        # Write now rather than leave a delayed save to race the unload.
        await self._store.async_save(self._data_to_save())

    def _data_to_save(self) -> dict[str, Any]:
        return {
            name: {
                "confirmed": sorted(flag.debouncer.confirmed),
                "stamp": flag.stamp,
                # Detail for the confirmed keys only, so a `cleared` event
                # after a restart can still name the host.
                "detail": {
                    k: flag.detail[k] for k in flag.debouncer.confirmed if k in flag.detail
                },
            }
            for name, flag in self._flags.items()
        }

    @callback
    def async_add_listener(self, update: CALLBACK_TYPE) -> CALLBACK_TYPE:
        """Entities subscribe here, not to the coordinators, so they are told
        after the monitor has moved -- including on a timer-driven flip that
        no coordinator refresh accompanies."""
        self._listeners.append(update)

        @callback
        def _remove() -> None:
            self._listeners.remove(update)

        return _remove

    @callback
    def _notify(self) -> None:
        for update in list(self._listeners):
            update()

    # -- policy --------------------------------------------------------------

    @property
    def policy(self) -> AlertPolicy:
        """Read live off the entry on every use, never cached: an options
        edit is live on the next observation, no reload."""
        return resolve_policy(self.entry.options)

    # -- observations --------------------------------------------------------

    @callback
    def _on_scan(self) -> None:
        view = self._scan.data
        if view is None:
            return
        flag = self._flags[FLAG_UNKNOWN_HOSTS]
        present: dict[str, dict[str, Any]] = {}
        for row in view.unmatched:
            mac = normalise_mac(row.get("mac"))
            if mac:
                present[mac] = row
        flag.detail.update(present)
        # ACKNOWLEDGED IS FORGOTTEN, NOT CLEARED -- see the module docstring.
        acked = {
            m for m in (normalise_mac(r.get("mac")) for r in view.acknowledged) if m
        }
        flag.debouncer.forget(acked)
        self._observe(
            FLAG_UNKNOWN_HOSTS,
            present.keys(),
            self._unknown_host_payload,
            stamp=view.inventory.generated_at,
        )

    @callback
    def _on_cve(self) -> None:
        data = self._cve.data or {}
        count = data.get(_CVE_KEY)
        if count is None:
            # Could not read. Not an absence -- see the module docstring.
            return
        flag = self._flags[FLAG_VULNERABILITIES]
        findings = data.get("findings") or []
        affected = [f for f in findings if f.get("disposition") == cpe.AFFECTED]
        flag.detail[_CVE_KEY] = {
            "count": int(count),
            "overdue": sum(1 for f in affected if f.get("overdue")),
            "ransomware_linked": sum(1 for f in affected if f.get("ransomware")),
            "affected": [
                {
                    "cve": f.get("cve"),
                    "product": f.get("product"),
                    "device": f.get("device"),
                    "version": f.get("version"),
                    "fixed_in": f.get("fixed_in"),
                }
                for f in affected[:MAX_DETAIL]
            ],
        }
        present = [_CVE_KEY] if int(count) > 0 else []
        self._observe(
            FLAG_VULNERABILITIES,
            present,
            self._vulnerability_payload,
            stamp=data.get("generated"),
        )

    def _observe(
        self, name: str, present, payload_fn: Callable[[Any], dict], stamp: Any
    ) -> None:
        flag = self._flags[name]
        policy = self.policy
        now = dt_util.utcnow()
        # ONE SCAN, ONE OBSERVATION. A stamp of None (nothing scanned yet) is
        # never counted either: there is no inventory to observe.
        if stamp is not None and stamp != flag.stamp:
            flag.stamp = stamp
            flag.last_observed = now.isoformat()
            transitions: Transitions = flag.debouncer.observe(present, policy)
            for key in transitions.asserted:
                self._fire(_rise_kind(name), payload_fn(key), now.timestamp(), policy)
            for key in transitions.cleared:
                self._fire(_fall_kind(name), payload_fn(key), now.timestamp(), policy)
            if transitions:
                self._store.async_delay_save(self._data_to_save, SAVE_DELAY)
        # The acknowledgement set may have moved without a new scan, and the
        # hold may have expired: the flag is re-derived on every publish.
        flag.wanted = bool(flag.debouncer.confirmed)
        self._propose(name, now.timestamp(), policy)
        self._notify()

    def _propose(self, name: str, now: float, policy: AlertPolicy) -> None:
        flag = self._flags[name]
        before = flag.held.state
        after = flag.held.propose(flag.wanted, now, policy)
        if after != flag.wanted and flag.held.held_until is not None:
            # Deferred. Come back the moment the hold ends rather than at the
            # next tick; one timer per flag, the newest deadline wins.
            self._schedule_retry(name, flag.held.held_until - now)
        elif name in self._retry_timers:
            self._retry_timers.pop(name)()
        if before != after:
            _LOGGER.info("%s flag %s", name, "raised" if after else "cleared")

    def _schedule_retry(self, name: str, delay: float) -> None:
        if name in self._retry_timers:
            self._retry_timers.pop(name)()

        @callback
        def _retry(_now) -> None:
            self._retry_timers.pop(name, None)
            self._propose(name, dt_util.utcnow().timestamp(), self.policy)
            self._notify()

        self._retry_timers[name] = async_call_later(self.hass, max(delay, 0.0) + 0.1, _retry)

    # -- events --------------------------------------------------------------

    def _fire(self, kind: str, payload: dict[str, Any], now: float, policy: AlertPolicy) -> None:
        if not self._limiter.allow(kind, now, policy):
            _LOGGER.info("%s suppressed by the event rate limit", kind)
            return
        self.hass.bus.async_fire(
            EVENT_TYPE, {"type": kind, "entry_id": self.entry.entry_id, **payload}
        )

    def _unknown_host_payload(self, mac: str) -> dict[str, Any]:
        row = self._flags[FLAG_UNKNOWN_HOSTS].detail.get(mac, {})
        return {
            "mac": row.get("mac") or mac,
            "ip": row.get("ip"),
            "hostname": row.get("hostname"),
            "vendor": row.get("vendor"),
            "os": row.get("os"),
            "open_ports": row.get("open_ports") or [],
        }

    def _vulnerability_payload(self, _key: str) -> dict[str, Any]:
        return dict(self._flags[FLAG_VULNERABILITIES].detail.get(_CVE_KEY, {}))

    # -- what the entities read ---------------------------------------------

    def is_on(self, name: str) -> bool:
        return self._flags[name].held.state

    def attributes(self, name: str) -> dict[str, Any]:
        """Everything a surface needs to explain a quiet or a noisy flag.

        `events_suppressed` is ALWAYS PRESENT, empty when nothing was dropped
        -- a declined signal is stated on the entity, never merely absent.
        """
        flag = self._flags[name]
        policy = self.policy
        now = dt_util.utcnow().timestamp()
        held_until = flag.held.held_until
        if held_until is not None and held_until <= now:
            held_until = None
        out: dict[str, Any] = {
            "pending": [
                self._pending_row(name, key, seen, policy.confirm_observations)
                for key, seen in flag.debouncer.pending.items()
            ][:MAX_DETAIL],
            "clearing": [
                self._pending_row(name, key, missed, policy.clear_observations)
                for key, missed in flag.debouncer.clearing.items()
            ][:MAX_DETAIL],
            "wanted": flag.wanted,
            "held_until": (
                dt_util.utc_from_timestamp(held_until).isoformat() if held_until else None
            ),
            "deferred_changes": flag.held.deferred,
            "last_observed": flag.last_observed,
            "events_sent_last_hour": {
                kind: self._limiter.sent_in_window(kind, now)
                for kind in (_rise_kind(name), _fall_kind(name))
            },
            "events_suppressed": {
                kind: n
                for kind, n in self._limiter.suppressed.items()
                if kind in (_rise_kind(name), _fall_kind(name))
            },
            "policy": policy.as_attributes(),
        }
        if name == FLAG_UNKNOWN_HOSTS:
            confirmed = sorted(flag.debouncer.confirmed)
            out["hosts"] = [self._unknown_host_payload(m) for m in confirmed[:MAX_DETAIL]]
            out["host_count"] = len(confirmed)
        else:
            out.update(flag.detail.get(_CVE_KEY, {"count": None, "affected": []}))
        return out

    def _pending_row(self, name: str, key: Any, seen: int, needed: int) -> dict[str, Any]:
        row: dict[str, Any] = {"observations": seen, "needed": needed}
        if name == FLAG_UNKNOWN_HOSTS:
            row.update(self._unknown_host_payload(key))
        return row


def _rise_kind(name: str) -> str:
    return (
        KIND_UNKNOWN_HOST_DETECTED
        if name == FLAG_UNKNOWN_HOSTS
        else KIND_VULNERABILITY_ACTIONABLE
    )


def _fall_kind(name: str) -> str:
    return (
        KIND_UNKNOWN_HOST_CLEARED
        if name == FLAG_UNKNOWN_HOSTS
        else KIND_VULNERABILITY_CLEARED
    )
