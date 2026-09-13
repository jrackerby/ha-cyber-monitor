"""The cyber_estate integration -- merge of estate_feeds, nvd_estate
and network_inventory under one config entry. See const.py for the full
merge rationale.

SETUP ORDER AND ITS CONSEQUENCE. feeds and cve coordinators NEVER raise --
both follow the "an unreadable source is a disposition, not a setup
failure" rule the standalone integrations were built on. scan CAN raise
ConfigEntryNotReady (missing nmap binary). Because all three now share one
config entry, a scan setup failure retries the WHOLE entry, including the
always-succeeding feeds/cve halves -- a real behaviour change from three
independent integrations, accepted because nmap already works on this host
today (the standalone network_inventory integration is loaded) and a
merged entry has one setup lifecycle by construction.
"""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceEntry

from .alerts import AlertMonitor, async_remove_alert_store
from .const import DOMAIN, PLATFORMS
from .cve.coordinator import NvdEstateCoordinator
from .feeds.coordinator import EstateFeedsCoordinator
from .runtime import KEY_ALERTS, KEY_SCAN, scan_coordinator_of
from .scan import (
    async_register_scanner_device,
    async_remove_scan_device,
    async_remove_scan_entry,
    async_setup_scan,
    async_unload_scan,
)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up all three subsystems under one entry."""
    feeds_coordinator = EstateFeedsCoordinator(hass)
    # async_refresh(), not async_config_entry_first_refresh(): the coordinator
    # never raises UpdateFailed (see feeds/coordinator.py), so the retry
    # machinery async_config_entry_first_refresh adds is dead weight here --
    # same reasoning the standalone estate_feeds integration documented.
    await feeds_coordinator.async_refresh()

    cve_coordinator = NvdEstateCoordinator(hass, entry)
    await cve_coordinator.async_config_entry_first_refresh()

    scan_coordinator = await async_setup_scan(hass, entry)
    # BEFORE the platforms below, not after: endpoint devices carry a
    # via_device_id pointing at the scanner, and that id has to name a row the
    # registry already holds or the endpoint entity raises instead of simply
    # going unparented. See async_register_scanner_device.
    async_register_scanner_device(hass, entry)

    # THE ONLY WRITE. Every read of this dict goes through runtime.py --
    # KEY_SCAN is the same constant the accessor there indexes with, so a
    # rename cannot land on this line and miss a reader.
    # STARTED BEFORE THE PLATFORMS ARE FORWARDED, so its coordinator listeners
    # are registered ahead of every entity's and run first on each refresh --
    # the binary sensors then read a flag the monitor has already moved.
    alerts = AlertMonitor(hass, entry, scan_coordinator, cve_coordinator)
    await alerts.async_start()
    entry.async_on_unload(alerts.async_stop)

    entry.runtime_data = {
        "feeds": feeds_coordinator,
        "cve": cve_coordinator,
        KEY_SCAN: scan_coordinator,
        KEY_ALERTS: alerts,
    }
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # A SAVED OPTION IS ACTED ON AT ONCE, AND STILL WITHOUT A RELOAD.
    # Acknowledged MACs came first; scan scope and the
    # sweep schedule through the same door. Reloading would re-run agent/local
    # setup (binary lookup, agent handshake) and, worse, restart the feeds and
    # CVE coordinators, for a change that touched none of them -- while the
    # scan coordinator re-reads all of it off the entry itself. The refresh is
    # what makes the change visible now rather than up to a tick later.
    entry.async_on_unload(entry.add_update_listener(_async_options_updated))
    return True


async def _async_options_updated(hass: HomeAssistant, entry: ConfigEntry) -> None:
    await scan_coordinator_of(entry).async_refresh()


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        async_unload_scan(hass)
    return unloaded


async def async_remove_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Forget scan's stored inventory and the alert monitor's confirmed set
    when the entry itself is removed.

    Only on REMOVAL, never on unload -- see scan/__init__.py's
    async_remove_scan_entry docstring. feeds and cve carry no persisted
    state of their own to clean up.
    """
    await async_remove_scan_entry(hass, entry)
    await async_remove_alert_store(hass, entry.entry_id)


async def async_remove_config_entry_device(
    hass: HomeAssistant,
    entry: ConfigEntry,
    device: DeviceEntry,
) -> bool:
    """Route device-removal requests to the owning subsystem.

    scan's devices (the scanner itself and every discovered endpoint) carry
    the REAL top-level DOMAIN in their identifiers (see scan/entity.py) and
    have real removability logic -- see async_remove_scan_device's
    docstring for why an endpoint that is still being seen refuses.

    feeds' and cve's own devices carry their LOCAL namespace strings
    ("estate_feeds", "nvd_estate") instead, precisely so they are
    distinguishable here. Neither is removable: both are single fixed
    devices that exist for the life of the entry, matching the standalone
    integrations' behaviour, which never implemented this hook at all (no
    hook means HA refuses removal by default).
    """
    if any(i[0] == DOMAIN for i in device.identifiers):
        scan_coordinator = scan_coordinator_of(entry)
        return await async_remove_scan_device(hass, entry, device, scan_coordinator)
    return False
