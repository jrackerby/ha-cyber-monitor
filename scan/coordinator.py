"""Fetch the inventory and join it to what Home Assistant already knows.

THE JOIN IS THE POINT OF THIS INTEGRATION. A scanner alone can say "78 things
answered"; Home Assistant alone can say how many device records it holds.
Neither can answer the question that matters -- *is there something on this
network that nothing here accounts for* -- because they key on different
things. The scanner knows MAC and IP; the registry knows manufacturer, model
and version. MAC is the one identifier both sides hold, so it is the join key.

THE DECISION ITSELF LIVES IN `join.py`, which imports nothing from Home
Assistant and is therefore testable directly. This module does only the things
that genuinely need the running instance: obtain a scan, and read the registry.

TWO MODES, ONE COORDINATOR. `agent` polls a remote scanner over HTTP; `local`
runs nmap in this container and keeps the inventory itself. They are branches
here rather than two components because everything downstream -- the join, the
sensors, the census, the device registry -- is identical either way. Which end
holds the nmap process is not a difference the entities should be able to see.

IN LOCAL MODE THE COORDINATOR TICK IS NOT A SCAN. It fires every few minutes
and asks whether either sweep is DUE. Scanning on every tick would put a
continuous SYN flood on the network, and tying the expensive service scan to the
cheap liveness sweep is the exact conflation that erased a night of service
data on the old scanner.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from ..const import DOMAIN  # real top-level domain -- see scan/const.py's note
from .api import (
    CannotConnect,
    Inventory,
    InvalidAuth,
    NetworkInventoryClient,
    NoInventoryYet,
    UnsupportedSchema,
)
from .const import (
    CONF_ACKNOWLEDGED_MACS,
    EMPTY_TARGET_SWEEPS,
    LOCAL_TICK,
    SCAN_NS,
    UPDATE_INTERVAL,
)
from .coverage import coverage, host_addresses, unreachable, update_streaks
from .join import JoinResult, join_hosts, normalise_mac
from .options import PROFILES as OPTION_PROFILES
from .scanner import NmapScanner, ScanBusy, ScanError
from .services_view import census, host_was_port_scanned
from .settings import ScanSettings, resolve_settings
from .ssh_probe import SshProber, SshResult, host_runs_ssh, ssh_ports
from .store import InventoryStore

_LOGGER = logging.getLogger(__name__)


def empty_targets_issue_id(config_entry_id: str | None) -> str:
    """The repair id for "these targets answer nothing", per config entry.

    ONE ISSUE PER ENTRY, NOT PER TARGET, so the condition can clear itself. A
    restart empties the streak table, and the first complete sweep afterwards
    either rewrites this issue with what it just measured or deletes it. A
    per-target issue could not do that for a target that has since been removed
    from the scope: the repair would outlive the setting it is about, and
    nothing left in the configuration would explain it.

    Derived rather than stored, so `async_remove_scan_entry` can clear the
    repair for an entry whose coordinator is already gone.
    """
    return f"empty_targets_{config_entry_id}"


@dataclass(slots=True)
class InventoryView:
    """The joined result. Everything the entities read comes from here."""

    inventory: Inventory
    join: JoinResult
    newest_port_scan: Any = None  # datetime | None
    # Per-profile timer/scan state. EMPTY IS A VALID VALUE and means the
    # control surface is unavailable, not that the scanner is idle -- the
    # switches and buttons read it and must not invent a state from a gap.
    profiles: dict[str, Any] = field(default_factory=dict)
    # SSH probe results keyed by normalised MAC. Absent means not probed.
    ssh: dict[str, SshResult] = field(default_factory=dict)
    scanning: bool = False
    current_scan: str | None = None
    # Set when service detection is impossible, so the UI can say why rather
    # than showing every host with no services and no explanation.
    service_detection_error: str | None = None

    @property
    def endpoints(self) -> dict[str, dict[str, Any]]:
        """Scanned hosts keyed by NORMALISED MAC.

        Hosts without a usable MAC are dropped rather than given a synthetic
        key: an identity derived from an IP changes with the lease, which
        would silently replace a device rather than update it.
        """
        out: dict[str, dict[str, Any]] = {}
        for host in self.inventory.hosts.values():
            mac = normalise_mac(host.get("mac"))
            if mac:
                out[mac] = host
        return out

    @property
    def live_endpoints(self) -> dict[str, dict[str, Any]]:
        """Endpoints the MOST RECENT scan actually saw, keyed by normalised MAC.

        `endpoints` IS NOT THIS SET, and reading it as though it were is the
        defect this property exists to end (GH-33). `endpoints` is the whole
        persisted inventory -- every host the integration has ever recorded --
        so a guard phrased as "is this host still being seen" and implemented
        against it answers "has this host ever existed", which is true of
        every device on the device page. Nothing could be deleted.

        `status` CANNOT ANSWER IT EITHER. `merge_inventory` only touches
        records present in a scan result, so a host that leaves the network
        keeps whatever `status` its last sighting recorded -- usually "up" --
        for as long as the record survives. Measured on a live estate: 185
        hosts tracked, 185 "up", including a subnet deleted days earlier.

        `last_seen` IS THE ONLY FIELD THAT TRACKS SIGHTINGS. Every host in one
        scan result is stamped with the same `ts`, so hosts seen together
        share a byte-identical string and "seen in the newest scan" is an
        exact comparison rather than a window that has to guess how long a
        device may sleep.

        A HOST WITH NO READABLE `last_seen` IS NOT REPORTED AS LIVE. We cannot
        show it is still answering, and the guard above it refuses an action
        the operator asked for -- so silence must not become a refusal. That
        is the mirror of `parse.prune`'s rule, where silence must not become a
        deletion: neither reading invents evidence, and each errs away from
        surprising the operator.
        """
        stamps = [
            h.get("last_seen") for h in self.inventory.hosts.values()
            if h.get("last_seen")
        ]
        if not stamps:
            return {}
        newest = max(stamps)

        out: dict[str, dict[str, Any]] = {}
        for host in self.inventory.hosts.values():
            if host.get("last_seen") != newest:
                continue
            mac = normalise_mac(host.get("mac"))
            if mac:
                out[mac] = host
        return out

    @property
    def service_census(self) -> dict[str, Any]:
        return census(self.inventory.hosts)

    # Convenience passthroughs so the entities do not reach two levels deep.
    @property
    def unknown_count(self) -> int:
        return self.join.unknown_count

    @property
    def unmatched(self) -> list[dict[str, Any]]:
        return self.join.unmatched

    @property
    def acknowledged_count(self) -> int:
        return self.join.acknowledged_count

    @property
    def acknowledged(self) -> list[dict[str, Any]]:
        return self.join.acknowledged

    @property
    def matched(self) -> int:
        return self.join.matched

    @property
    def unjoinable(self) -> int:
        return self.join.unjoinable

    @property
    def hosts_up(self) -> int:
        return self.join.hosts_up

    @property
    def exposed_services(self) -> int:
        return self.join.exposed_services

    @property
    def hosts_with_port_data(self) -> int:
        return self.join.hosts_with_port_data

    @property
    def hosts_never_port_scanned(self) -> int:
        """Hosts nobody has ever port-scanned.

        Published as a first-class number rather than derived by subtraction,
        because it is the size of this instrument's blind spot and an operator
        should not have to compute it to find out how much of the network the
        service answers do not cover.
        """
        return sum(
            1 for h in self.inventory.hosts.values() if not host_was_port_scanned(h)
        )


class NetworkInventoryCoordinator(DataUpdateCoordinator[InventoryView]):
    """Base: holds the join and the registry read, whatever the source."""

    def __init__(
        self, hass: HomeAssistant, update_interval, config_entry_id: str | None = None
    ) -> None:
        super().__init__(
            hass, _LOGGER, name=SCAN_NS, update_interval=update_interval
        )
        # Needed by `_known_macs` to recognise its own device records. Optional
        # so a caller that has not got one yet degrades to the old behaviour
        # rather than crashing -- but every real caller passes it.
        self.config_entry_id = config_entry_id

    def _known_macs(self) -> list[str]:
        """Every MAC the device registry holds, EXCEPT the ones we created.

        A PATTERN VALIDATED AGAINST ITSELF IS NOT VALIDATED. This
        integration creates a device per scanned endpoint, carrying that
        endpoint's MAC as a network connection -- so a naive read of the
        registry finds every host we have ever scanned already "known", by us,
        and `unknown_hosts` decays to zero as the inventory grows. The detector
        then reports a clean network precisely because it has been running a
        while, which is the failure it exists to prevent.

        This is the acknowledgement circularity arriving from a second source: there it
        was the scanner's own MQTT discovery, here it is our own device
        records. The rule is the same -- a device known ONLY to us is not
        corroboration. A device we share with another integration is, so the
        test is on sole ownership rather than on our presence.

        Handed over unnormalised on purpose: `join_hosts` normalises both sides
        through one function, so this cannot introduce a format mismatch.
        """
        registry = dr.async_get(self.hass)
        ours = self.config_entry_id
        return [
            conn_value
            # ITERATED, NOT .values(). `device_registry.devices`
            # as a MAPPING is deprecated and stops working in HA 2027.9;
            # iterating the container yields DeviceEntry directly, which is
            # the supported form. Same objects, same order, no lookup.
            for device in registry.devices
            if not (ours and device.config_entries == {ours})
            for conn_type, conn_value in device.connections
            if conn_type == dr.CONNECTION_NETWORK_MAC
        ]

    def _acknowledged_macs(self) -> list[str]:
        """MACs an operator has explicitly decided are fine, from the options flow.

        The first defect: `unknown_hosts` had no way to reach zero for
        a real, explained case (a multi-NIC device whose ARP-visible MAC
        differs from the one the device registry holds -- the UDM Pro).
        Read live off the config entry on every refresh rather than cached
        at setup, so acknowledging a host takes effect on the coordinator's
        own next tick without a full entry reload.
        """
        if not self.config_entry_id:
            return []
        entry = self.hass.config_entries.async_get_entry(self.config_entry_id)
        if entry is None:
            return []
        return list(entry.options.get(CONF_ACKNOWLEDGED_MACS, []))

    # -- control surface -----------------------------------------------------
    #
    # DECLARED ON THE BASE so the buttons and switches never branch on mode.
    # They previously reached into `coordinator.client`, which only exists in
    # agent mode -- a control that works in one mode and raises AttributeError
    # in the other is the kind of fork this component is written to avoid.

    async def async_request_scan(self, profile: str) -> None:
        raise NotImplementedError

    async def async_set_schedule(self, profile: str, enabled: bool) -> None:
        raise NotImplementedError


class AgentCoordinator(NetworkInventoryCoordinator):
    """Polls a remote scanner agent over HTTP."""

    def __init__(
        self,
        hass: HomeAssistant,
        client: NetworkInventoryClient,
        config_entry_id: str | None = None,
    ) -> None:
        super().__init__(hass, UPDATE_INTERVAL, config_entry_id)
        self.client = client

    async def _async_update_data(self) -> InventoryView:
        try:
            inventory = await self.client.async_get_inventory()
        except InvalidAuth as err:
            raise UpdateFailed(f"agent rejected the token: {err}") from err
        except NoInventoryYet as err:
            raise UpdateFailed(
                "agent is reachable but no scan has completed yet"
            ) from err
        except UnsupportedSchema as err:
            raise UpdateFailed(str(err)) from err
        except CannotConnect as err:
            # Every entity goes unavailable, and that is the honest outcome: we
            # did not measure the network, so we must not publish a number
            # about it. A zero here would render as "nothing unknown on your
            # network" at exactly the moment we can no longer tell.
            raise UpdateFailed(f"cannot reach agent: {err}") from err

        # Status is fetched AFTER the inventory and cannot fail the refresh:
        # async_get_status swallows its own transport errors and returns {}.
        # Losing the control surface must not take the data down with it.
        profiles = await self.client.async_get_status()

        result = join_hosts(
            inventory.hosts, self._known_macs(), self._acknowledged_macs()
        )
        return InventoryView(
            inventory=inventory,
            join=result,
            newest_port_scan=_newest_port_scan(inventory.hosts),
            profiles=profiles,
        )

    async def async_request_scan(self, profile: str) -> None:
        await self.client.async_request_scan(profile)

    async def async_set_schedule(self, profile: str, enabled: bool) -> None:
        await self.client.async_set_schedule(profile, enabled)


class LocalCoordinator(NetworkInventoryCoordinator):
    """Runs nmap in this container and owns the inventory."""

    def __init__(
        self,
        hass: HomeAssistant,
        scanner: NmapScanner,
        store: InventoryStore,
        settings: ScanSettings,
        stale_days: int,
        prober: SshProber | None = None,
        config_entry_id: str | None = None,
    ) -> None:
        super().__init__(hass, LOCAL_TICK, config_entry_id)
        self.scanner = scanner
        self.store = store
        self.stale_days = stale_days
        self.prober = prober
        # THE FALLBACK, NOT THE SOURCE. Scope and schedule are re-read off the
        # config entry on every use (see `settings`), so an options edit takes
        # effect on the next tick rather than at the next reload. This copy is
        # what a coordinator constructed without a reachable entry uses, and it
        # is what setup resolved, so the two agree at construction by
        # definition.
        self._settings = settings

        self._last_discovery: datetime | None = None
        self._last_service_scan: datetime | None = None
        self._last_ssh_probe: datetime | None = None
        self._ssh: dict[str, SshResult] = {}
        self._service_error: str | None = None
        self._enabled: dict[str, bool] = {"discovery": True, "standard": True}
        # Which sweeps are in flight. The scanner's lock already serialises
        # nmap itself; this stops a five-minute tick from queueing a hundred
        # coroutines behind one long scan.
        self._running: dict[str, bool] = {}
        self._clocks_seeded = False
        # The scope the last full sweep actually covered. None until one has
        # run in this process -- see `_scope_changed`.
        self._swept_scope: tuple[frozenset[str], frozenset[str]] | None = None
        # Per-target count of consecutive full sweeps that found nothing there.
        # Empty at construction, so what this process reports is what this
        # process measured -- see `_record_coverage`.
        self._empty_sweeps: dict[str, int] = {}

    # -- scope and schedule --------------------------------------------------

    @property
    def settings(self) -> ScanSettings:
        """Scope and schedule as they stand RIGHT NOW.

        Read live off the config entry rather than cached at setup, for the
        same reason `_acknowledged_macs` is: an options edit that only took
        effect on the next full reload would mean adding a subnet costs a
        restart of all three subsystems, and the operator has no way to tell
        whether the change is live yet. Everything that needs scope or
        schedule comes through here and through `resolve_settings` beneath it,
        so the form's defaults and the sweep's targets cannot disagree
        (one accessor, never two paths).
        """
        entry = None
        if self.config_entry_id:
            entry = self.hass.config_entries.async_get_entry(self.config_entry_id)
        if entry is None:
            return self._settings
        return resolve_settings(entry.data, entry.options)

    @property
    def targets(self) -> list[str]:
        return list(self.settings.targets)

    @property
    def exclude(self) -> list[str]:
        return list(self.settings.exclude)

    # -- scheduling ----------------------------------------------------------

    def _seed_clocks_from_store(self) -> None:
        """Recover the due-clocks from persisted scan timestamps, once.

        THE CLOCKS WERE IN MEMORY ONLY, so every Home Assistant restart made
        both sweeps immediately due and fired a full service scan of the whole
        subnet. Measured: a restart put a `-sV` sweep on the wire within
        seconds, and a day with several restarts would scan the network several
        times over for no new information.

        The store already records when each kind of scan last landed, so the
        answer was persisted all along and merely not read back. Discovery is
        seeded from `last_scan` (any sweep refreshes liveness) and the service
        sweep from `last_port_scan` (only a port scan refreshes ports) --
        the same two-clock distinction the sensors expose.
        """
        if self._clocks_seeded:
            return
        self._clocks_seeded = True
        if self._last_discovery is None:
            self._last_discovery = dt_util.parse_datetime(self.store.last_scan or "")
        if self._last_service_scan is None:
            self._last_service_scan = dt_util.parse_datetime(
                self.store.last_port_scan or ""
            )

    def _due(self, profile: str, last: datetime | None, interval) -> bool:
        if not self._enabled.get(profile, True):
            return False
        if last is None:
            return True
        return dt_util.utcnow() - last >= interval

    @staticmethod
    def _scope_of(settings: ScanSettings) -> tuple[frozenset[str], frozenset[str]]:
        """What a sweep covers, as SETS. Reordering the same two subnets in the
        text field is not a scope change and must not cost a scan."""
        return frozenset(settings.targets), frozenset(settings.exclude)

    def _scope_changed(self, settings: ScanSettings) -> bool:
        """True when the live scope is not the one last actually swept.

        A SUBNET ADDED AT 14:00 IS SWEPT AT 14:00, NOT AT 15:00. Waiting for
        the discovery clock would leave the new range unmeasured for up to a
        full interval while the entities report a host count that looks
        settled, and nothing on any surface would say the number excludes the
        range that was just added -- an operator who adds a management VLAN
        and sees no new hosts reads that as "nothing is there".

        EXCLUDE COUNTS TOO, because removing an exclusion widens the scope
        exactly as much as adding a target does. Narrowing it -- adding a
        target or an exclusion -- costs one cheap sweep it did not strictly
        need, which is the right way round: the alternative is a widening
        nobody measures.

        Only DISCOVERY is forced. A service sweep of a fresh /24 runs for many
        minutes and its clock is measured in days; forcing one on every edit
        would make correcting a typo in the exclude list an expensive act.
        The new range gets its ports read on the next scheduled service sweep,
        or immediately from the Scan now button.

        None means nothing has been swept in this process yet, so the clocks
        seeded from the store govern alone -- otherwise every restart would
        force a sweep, which is exactly what `_seed_clocks_from_store` exists
        to stop.
        """
        return (
            self._swept_scope is not None
            and self._scope_of(settings) != self._swept_scope
        )

    async def _async_update_data(self) -> InventoryView:
        """One tick. Launches whichever sweeps are due and returns immediately.

        A TICK MUST NEVER AWAIT A SCAN. The first refresh happens inside
        `async_config_entry_first_refresh`, and a service sweep of a /24 runs
        for many minutes -- awaiting one there blocks integration setup past
        Home Assistant's patience and the entry fails to load, which reads as
        a broken integration rather than as a scan still running. The same is
        true of every later tick: the coordinator's job is to publish what is
        known now, not to be the thing that takes a quarter of an hour.

        Sweeps therefore run as background tasks and call
        `async_set_updated_data` when they finish. The scanner's own lock makes
        a second launch harmless -- it raises ScanBusy and is swallowed -- so a
        fast tick interval cannot pile scans on top of each other.
        """
        await self.store.async_load()
        self._seed_clocks_from_store()
        settings = self.settings

        # Service scan is checked first despite being the more expensive sweep --
        # it also runs on the longer interval, so this ordering is what makes it
        # due least often, not a cost ordering. Only one scan is launched per tick.
        if self._due("standard", self._last_service_scan, settings.service_interval):
            self._launch("service scan", self._run_service_scan())
        elif self._due(
            "discovery", self._last_discovery, settings.discovery_interval
        ) or (
            self._enabled.get("discovery", True)
            and self._scope_changed(settings)
        ):
            self._launch("discovery", self._run_discovery())

        if self.prober and self._due(
            "ssh", self._last_ssh_probe, settings.ssh_interval
        ):
            self._launch("ssh probe", self._run_ssh_probe())

        # A tick that scanned nothing still republishes: the registry may have
        # changed underneath us, and the join is what turns that into an answer.
        return self._build_view()

    def _launch(self, label: str, coro) -> None:
        """Run a sweep in the background and publish when it lands.

        The due-clock is moved by the sweep itself, not here, so a launch that
        fails to start leaves the sweep due rather than silently skipping it
        until the next interval.
        """
        if self._running.get(label):
            coro.close()
            return

        async def _wrap() -> None:
            self._running[label] = True
            try:
                await coro
            except Exception:  # noqa: BLE001 - a sweep must not kill the tick
                _LOGGER.exception("%s failed", label)
            finally:
                self._running[label] = False
                # PUBLISH WHATEVER HAPPENED, including a failure: the view
                # carries `scanning` and the service error, and leaving it
                # unpublished would show a scan running forever.
                self.async_set_updated_data(self._build_view())

        self.hass.async_create_task(_wrap())

    async def _run_discovery(self) -> None:
        # Read ONCE and swept with what was read. Re-reading `self.settings`
        # for the stamp below could record a scope the sweep never covered, if
        # the options changed while nmap was running.
        settings = self.settings
        try:
            result = await self.scanner.async_scan(
                list(settings.targets),
                exclude=list(settings.exclude),
                discovery_only=True,
                label="discovery",
            )
        except ScanBusy:
            # Not an error. An on-demand scan is running and will refresh
            # liveness itself; retrying next tick is correct.
            return
        except ScanError as err:
            # STAMPED ON FAILURE, exactly as the service sweep below is, and
            # for the same reason: a permanently broken scan must not retry on
            # every single tick. Neither stamp moved here before, so a sweep
            # that could never finish re-fired every LOCAL_TICK forever -- the
            # clock stayed due AND, after a scope edit, `_scope_changed` stayed
            # true. Measured: 31 sweeps in 9.4 hours against an hourly
            # interval, each burning the full timeout, nmap running back to
            # back (GH-34).
            #
            # THE SCOPE STAMP GOES TOO, and it is the less obvious half. With
            # only the clock stamped, `_scope_changed` alone still re-launches
            # on every tick after an edit. An attempt covered the scope it
            # attempted; the sweep retries on its ordinary clock, which is the
            # backoff a repeated failure needs.
            _LOGGER.warning("discovery sweep failed: %s", err)
            self._last_discovery = dt_util.utcnow()
            self._swept_scope = self._scope_of(settings)
            return
        self._last_discovery = dt_util.utcnow()
        self._fold_in_full_sweep(settings, result, prune=True)

    async def _run_service_scan(self) -> None:
        keys = list(OPTION_PROFILES["standard"])
        settings = self.settings
        try:
            result = await self.scanner.async_scan(
                list(settings.targets),
                option_keys=keys,
                exclude=list(settings.exclude),
                label="service scan",
            )
        except ScanBusy:
            return
        except ScanError as err:
            # RECORDED ON THE VIEW, not only in the log. Without the script
            # engine every service scan fails identically and forever, and a
            # log line nobody reads would leave the network looking like it
            # simply runs no services.
            self._service_error = str(err)
            _LOGGER.warning("service scan failed: %s", err)
            # Still mark it attempted, so a permanently broken scan does not
            # retry on every single tick.
            self._last_service_scan = dt_util.utcnow()
            return

        self._service_error = None
        self._last_service_scan = dt_util.utcnow()
        # A liveness sweep is implied by a service scan, so the discovery clock
        # resets too -- otherwise the next tick immediately runs a redundant one.
        self._last_discovery = self._last_service_scan
        self._fold_in_full_sweep(settings, result, prune=True)

    async def _run_ssh_probe(self) -> None:
        """Probe every host seen offering ssh. Never probes an unscanned host.

        THE INTERVAL IS ONLY SPENT IF THERE WAS SOMETHING TO PROBE. On a fresh
        entry the first tick fires before any scan has landed, so the probe
        finds an empty inventory -- and stamping the clock there would mean the
        first real answer arrived six hours later, with every SSH host reading
        unknown in between. Measured on exactly that first setup.
        """
        assert self.prober is not None
        results: dict[str, SshResult] = {}
        candidates = 0
        for host in self.store.hosts.values():
            mac = normalise_mac(host.get("mac"))
            address = host.get("ip")
            if not mac or not address:
                continue
            if host_runs_ssh(host) is not True:
                # Nothing to probe. The sensor derives `no_ssh` versus
                # `never_scanned` from the host record itself, so recording a
                # placeholder here would only give it a second, staler source.
                continue
            candidates += 1
            ports = ssh_ports(host) or [22]
            try:
                results[mac] = await self.prober.async_probe(address, ports[0])
            except Exception as err:  # noqa: BLE001 - one host must not stop the pass
                _LOGGER.debug("ssh probe failed for %s: %s", address, err)

        if not candidates:
            # Nothing to measure, so nothing was measured. Leaving the clock
            # unstamped keeps the probe due, and the next tick after the first
            # scan lands runs it for real.
            return

        self._last_ssh_probe = dt_util.utcnow()
        self._ssh = results

    # -- folding a whole-scope sweep back in ----------------------------------

    def _fold_in_full_sweep(
        self, settings: ScanSettings, result, *, prune: bool
    ) -> None:
        """Record what a sweep of the WHOLE live scope covered, and keep it.

        THREE PATHS RUN A FULL SWEEP and each has to do the same three things:
        stamp the scope it actually covered, measure which targets answered,
        and merge the hosts into the store. They were three copies, and one of
        them -- the on-demand `discovery` profile behind the Scan now button --
        did the first and neither of the others, so that press put a real sweep
        on the wire, moved the discovery clock (suppressing the next scheduled
        sweep for a full interval) and then threw away everything it found
        (GH-31). A new host plugged in and scanned for deliberately did not
        appear, and nothing said why. One function, three callers, so the next
        path added cannot quietly omit a step.

        PRUNING IS THE ONE THING THEY DO NOT SHARE, so it is a required keyword
        rather than a default: SCHEDULED SWEEPS AGE THE INVENTORY, OPERATOR-
        INITIATED ONES NEVER DO. Forgetting a host destroys its `first_seen`,
        which no amount of rescanning recovers, so it belongs to the clock that
        runs whether anybody is watching -- not to a button somebody pressed
        for an unrelated reason. `async_run_custom_scan` already refuses to
        prune for the narrower version of the same argument (it is commonly
        aimed at one host); this is that rule stated once for every on-demand
        path, including the whole-scope ones, rather than per call site.

        `store.apply_scan` still refuses to prune an INCOMPLETE sweep whatever
        it is passed, so `prune=True` means "age the inventory if this sweep is
        entitled to", never "age it regardless".
        """
        # STAMPS THE SCOPE, not just the clock. A sweep that moved the clock
        # without recording what it covered would leave the next tick seeing an
        # unswept scope and launching an identical sweep -- pressing Scan now
        # right after adding a subnet would scan twice.
        self._swept_scope = self._scope_of(settings)
        self._record_coverage(settings, result)
        self.store.apply_scan(
            result.hosts,
            complete=result.complete,
            stale_days=self.stale_days if prune else None,
        )

    # -- did the targets answer at all ---------------------------------------

    def _record_coverage(self, settings: ScanSettings, result) -> None:
        """Notice a configured target that a full sweep found nothing in.

        THIS IS THE ONE THING A CLEAN REPORT CANNOT DISTINGUISH FROM ITSELF.
        After the estate was re-addressed, three deleted subnets were swept for
        a day: no error, no finding, no unknown host -- identical output to a
        quiet network, and it surfaced only because an unrelated IPS started
        mailing about a host enumerating dead ranges (GH-29). An empty target
        is not proof the range is gone, so this reports rather than acts.

        ONLY A COMPLETE SWEEP COUNTS. `ScanResult.complete` is False when nmap
        exited non-zero or was killed mid-run, and the repo's rule for that
        case is already written down in `store.apply_scan`: the hosts present
        are real, the ABSENCE of a host means nothing. Counting an interrupted
        sweep here would let one timeout start a streak toward announcing that
        the network has disappeared.
        """
        if not result.complete:
            return

        found = coverage(
            settings.targets, settings.exclude, host_addresses(result.hosts)
        )
        self._empty_sweeps = update_streaks(self._empty_sweeps, found)
        self._sync_empty_target_issue()

    def _sync_empty_target_issue(self) -> None:
        """Raise, rewrite or clear the repair for targets that answer nothing.

        A REPAIR RATHER THAN A LOG LINE, because the failure mode is that
        nobody was told. The log already carries every sweep; what was missing
        was something in front of the operator saying the scanner is sweeping
        address space that answers nothing at all. It is not fixable in place
        -- the fix is an edit to the scan scope, which lives in the options
        flow and is where the description points.
        """
        dead = unreachable(self._empty_sweeps, EMPTY_TARGET_SWEEPS)
        if not dead:
            # Unconditional, and cheap when there is nothing to delete. This is
            # what clears a repair raised before a restart or before the scope
            # was corrected, without this process having to remember raising it.
            ir.async_delete_issue(
                self.hass, DOMAIN, empty_targets_issue_id(self.config_entry_id)
            )
            return

        _LOGGER.warning(
            "configured scan target(s) %s have answered with no hosts for %d "
            "consecutive full sweeps; the address space may no longer exist",
            ", ".join(dead),
            EMPTY_TARGET_SWEEPS,
        )
        ir.async_create_issue(
            self.hass,
            DOMAIN,
            empty_targets_issue_id(self.config_entry_id),
            is_fixable=False,
            severity=ir.IssueSeverity.WARNING,
            translation_key="empty_targets",
            translation_placeholders={
                "targets": ", ".join(dead),
                "sweeps": str(EMPTY_TARGET_SWEEPS),
            },
        )

    # -- on demand -----------------------------------------------------------

    async def async_run_custom_scan(
        self,
        targets: list[str] | None = None,
        option_keys: list[str] | None = None,
        label: str = "custom scan",
    ):
        """Run a user-requested scan now and fold the result in.

        Raises ScanBusy / ScanError / InvalidScanRequest to the caller so the
        service call reports what happened. A scan that silently did nothing is
        indistinguishable from one that found nothing.
        """
        result = await self.scanner.async_scan(
            targets or self.targets,
            option_keys=option_keys,
            exclude=self.exclude,
            label=label,
        )
        await self.store.async_load()
        # AN ON-DEMAND SCAN NEVER PRUNES. It is commonly aimed at one host, and
        # letting a single-host scan age every other record toward deletion
        # would quietly forget the network a scan at a time.
        self.store.apply_scan(result.hosts, complete=result.complete, stale_days=None)
        if any(h.get("ports_scanned") for h in result.hosts.values()):
            self._last_service_scan = dt_util.utcnow()
        self.async_set_updated_data(self._build_view())
        return result

    async def async_request_scan(self, profile: str) -> None:
        """Run a named profile now.

        `discovery` is not expressible through the option vocabulary -- it is
        the ABSENCE of port scanning rather than a modifier on it -- so it is
        dispatched separately rather than being given a fake option set.
        """
        if profile == "discovery":
            settings = self.settings
            result = await self.scanner.async_scan(
                list(settings.targets), exclude=list(settings.exclude),
                discovery_only=True, label="discovery",
            )
            self._last_discovery = dt_util.utcnow()
            await self.store.async_load()
            # THE RESULT IS BOUND AND KEPT. It used to be discarded: this
            # branch swept the whole scope, stamped the clock and published the
            # inventory exactly as it stood before the scan, so pressing Scan
            # now for this profile cost a sweep, suppressed the next scheduled
            # one for a full interval, and recorded nothing (GH-31).
            # `prune=False` because a sweep somebody asked for never ages the
            # inventory -- see `_fold_in_full_sweep`.
            self._fold_in_full_sweep(settings, result, prune=False)
            self.async_set_updated_data(self._build_view())
            return
        keys = list(OPTION_PROFILES.get(profile, ()))
        await self.async_run_custom_scan(option_keys=keys, label=profile)

    async def async_set_schedule(self, profile: str, enabled: bool) -> None:
        """Enable or disable a scheduled sweep.

        A DISABLED SWEEP IS SUPPRESSED, NEVER RESCHEDULED FAR AHEAD. Encoding
        "off" as a due-time in the year 3000 would make `timer_enabled` a guess
        derived from a date, and the switch would then report whatever that
        guess happened to say rather than what was asked for.
        """
        self._enabled[profile] = enabled
        self.async_set_updated_data(self._build_view())

    # -- view ----------------------------------------------------------------

    def _build_view(self) -> InventoryView:
        hosts = self.store.hosts
        generated = _epoch(self.store.last_scan)
        inventory = Inventory(
            schema_version=1, generated_at=generated, hosts=hosts
        )
        return InventoryView(
            inventory=inventory,
            join=join_hosts(hosts, self._known_macs(), self._acknowledged_macs()),
            newest_port_scan=dt_util.parse_datetime(self.store.last_port_scan or ""),
            profiles=self._profile_state(),
            ssh=dict(self._ssh),
            scanning=self.scanner.busy,
            current_scan=self.scanner.current_scan,
            service_detection_error=self._service_error,
        )

    def _profile_state(self) -> dict[str, Any]:
        """Schedule state in the same shape the agent reports, so the switches
        and buttons do not need to know which mode they are running in."""
        discovery_on = self._enabled.get("discovery", True)
        standard_on = self._enabled.get("standard", True)
        # THE LIVE INTERVALS, not the defaults. `next_run` is the only place a
        # schedule change becomes visible on a surface, so reading a constant
        # here would leave the switch printing the old cadence indefinitely
        # after an options edit -- a control that had accepted the change and
        # then denied it.
        settings = self.settings
        return {
            "discovery": {
                "timer_enabled": discovery_on,
                # NEXT RUN IS NULL WHEN SUPPRESSED, never a stale date. A time
                # printed beside a disabled schedule reads as one that is still
                # coming.
                "next_run": _iso(self._last_discovery, settings.discovery_interval)
                if discovery_on
                else None,
                "last_run": _iso(self._last_discovery, None),
                "scanning": self.scanner.current_scan == "discovery",
                "last_result": None,
            },
            "standard": {
                "timer_enabled": standard_on,
                "next_run": _iso(self._last_service_scan, settings.service_interval)
                if standard_on
                else None,
                "last_run": _iso(self._last_service_scan, None),
                "scanning": self.scanner.current_scan == "service scan",
                "last_result": "failed" if self._service_error else None,
            },
        }


def _epoch(iso: str | None) -> int:
    parsed = dt_util.parse_datetime(iso or "")
    if parsed is None:
        return 0
    return int(parsed.timestamp())


def _iso(when: datetime | None, add) -> str | None:
    if when is None:
        return None
    return (when + add).isoformat() if add else when.isoformat()


def _newest_port_scan(hosts: dict[str, dict[str, Any]]) -> Any:
    """Most recent time any host had its PORTS observed.

    Not the same as inventory freshness. A liveness-only sweep refreshes the
    inventory hourly while port data ages for a day or more, so tracking only
    the inventory would report a healthy feed while service scanning was dead.
    """
    newest = None
    for host in hosts.values():
        raw = host.get("ports_scanned_at")
        if not raw:
            continue
        parsed = dt_util.parse_datetime(raw)
        if parsed and (newest is None or parsed > newest):
            newest = parsed
    return newest
