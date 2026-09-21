"""Scan subsystem setup -- merge of the standalone network_inventory
integration into cyber_estate.

Local/agent branching, ConfigEntryNotReady handling, SSH prober wiring and
device-removal semantics are preserved verbatim from the standalone
integration's __init__.py. What changed is ownership: this module no longer
owns a config entry, a manifest, or PLATFORMS -- cyber_estate's top-level
__init__.py does, and calls into the functions here for the scan third of a
combined entry. entry.runtime_data is now a dict of all three subsystems'
coordinators, not this coordinator alone, so nothing here writes to it.
"""

from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.device_registry import DeviceEntry

from ..const import DOMAIN  # real top-level domain -- see scan/const.py's note
from .api import NetworkInventoryClient
from .const import (
    CONF_DATADIR,
    CONF_HOST,
    CONF_MODE,
    CONF_PORT,
    CONF_SSH_ENABLED,
    CONF_SSH_KEY,
    CONF_SSH_USERS,
    CONF_TOKEN,
    CONF_USE_TLS,
    CONF_VERIFY_SSL,
    MODE_LOCAL,
)
from .coordinator import (
    AgentCoordinator,
    LocalCoordinator,
    NetworkInventoryCoordinator,
    empty_targets_issue_id,
)
from .entity import scanner_device_info
from .scan_service import async_register_services, async_unregister_services
from .scanner import find_nmap
from .settings import resolve_settings, resolve_stale_days, split_list
from .ssh_probe import SshProber, find_ssh
from .store import InventoryStore

_LOGGER = logging.getLogger(__name__)


def _dir_exists(path: str) -> bool:
    import os

    return os.path.isdir(path)


async def async_setup_scan(
    hass: HomeAssistant, entry: ConfigEntry
) -> NetworkInventoryCoordinator:
    """Set up one scanner -- local or remote -- from the merged config entry.

    Raises ConfigEntryNotReady on failure, so a scanner that is merely
    rebooting retries the WHOLE cyber_estate entry instead of leaving a
    half-configured integration behind. That is a slightly wider blast
    radius than the standalone integration had (a scan-only outage now
    also retries feeds/CVE setup), accepted because a merged entry has one
    setup lifecycle by construction -- see the merge note above.
    """
    if entry.data.get(CONF_MODE) == MODE_LOCAL:
        coordinator = await _async_setup_local(hass, entry)
    else:
        coordinator = _setup_agent(hass, entry)

    await coordinator.async_config_entry_first_refresh()
    async_register_services(hass)
    return coordinator


def _setup_agent(hass: HomeAssistant, entry: ConfigEntry) -> AgentCoordinator:
    client = NetworkInventoryClient(
        session=async_get_clientsession(hass),
        host=entry.data[CONF_HOST],
        port=entry.data[CONF_PORT],
        token=entry.data[CONF_TOKEN],
        use_tls=entry.data.get(CONF_USE_TLS, False),
        verify_ssl=entry.data.get(CONF_VERIFY_SSL, True),
    )
    return AgentCoordinator(hass, client, config_entry_id=entry.entry_id)


async def _async_setup_local(
    hass: HomeAssistant, entry: ConfigEntry
) -> LocalCoordinator:
    """Wire up in-container scanning.

    THE BINARY IS RESOLVED AT SETUP, NOT PER SCAN, and its absence is a setup
    failure rather than a scan failure. An entry that loads cleanly and then
    fails every sweep is worse than one that refuses: by the time anything goes
    wrong the operator has left the dialog and the reason is only in the log.
    """
    binary = await hass.async_add_executor_job(find_nmap)
    if not binary:
        raise ConfigEntryNotReady(
            "nmap is not available in this Home Assistant container"
        )

    datadir = entry.data.get(CONF_DATADIR) or None
    if datadir:
        exists = await hass.async_add_executor_job(_dir_exists, datadir)
        if not exists:
            # NOT fatal, and deliberately so: port scanning still works without
            # the script engine. But it is logged loudly and carried on the
            # scanner, because every service-detection scan will now refuse,
            # and "no services found" must never be the way that is discovered.
            _LOGGER.error(
                "nmap data directory %s does not exist; service and version "
                "detection will be unavailable until it does",
                datadir,
            )
            datadir = None

    scanner_binary = binary
    from .scanner import NmapScanner

    scanner = NmapScanner(hass, scanner_binary, datadir=datadir)
    store = InventoryStore(hass, entry.entry_id)
    await store.async_load()

    prober = None
    if entry.data.get(CONF_SSH_ENABLED):
        ssh_binary = await hass.async_add_executor_job(find_ssh)
        key = entry.data.get(CONF_SSH_KEY)
        users = split_list(entry.data.get(CONF_SSH_USERS))
        if ssh_binary and key and users:
            prober = SshProber(hass, ssh_binary, key, users)
        else:
            _LOGGER.warning(
                "ssh probing was requested but is not configurable "
                "(ssh=%s, key=%s, users=%s); it will be skipped",
                bool(ssh_binary), bool(key), len(users),
            )

    return LocalCoordinator(
        hass,
        scanner=scanner,
        store=store,
        # RESOLVED HERE ONLY AS THE FALLBACK. The coordinator re-reads the
        # entry on every use so an options edit reaches the next
        # sweep without a reload; this is what it falls back to if the entry
        # cannot be read.
        settings=resolve_settings(entry.data, entry.options),
        # `data` ALONE, AND ONLY HERE, BY DESIGN -- not the oversight the pair
        # of lines looks like (GH-29). `stale_days` is edited by RECONFIGURE,
        # which writes `entry.data` and reloads, so this read is how an edit
        # takes effect; the options flow deliberately does not offer it,
        # because a key with two editors has one that is silently inert (see
        # `config_flow.py`'s header). `resolve_stale_days` carries the rest of
        # the reasoning and the clamp that keeps a hand-edited number from
        # deleting the inventory.
        stale_days=resolve_stale_days(entry.data),
        prober=prober,
        config_entry_id=entry.entry_id,
    )


@callback
def async_register_scanner_device(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Create the scanner's device row before any platform is forwarded.

    ENDPOINTS POINT AT THIS DEVICE, so it has to exist first. Under the
    deprecated `via_device` that ordering was not load-bearing: the registry
    resolved the identifier tuple itself and, on a miss, logged and left the
    endpoint unparented -- which is why on a first-ever setup every endpoint
    landed at the top level and only picked up its parent on the NEXT
    restart, once the button/switch platforms had created the scanner.
    `via_device_id` does not forgive that -- an unknown id raises
    DeviceInfoError -- so registering here turns a tolerated race into no
    race at all, and first boot now links the same as every later one.

    Idempotent: `async_get_or_create` on identifiers that already exist
    returns the existing row rather than adding a second.
    """
    dr.async_get(hass).async_get_or_create(
        config_entry_id=entry.entry_id,
        **scanner_device_info(
            entry.entry_id,
            entry.title,
            # .get, not [] -- local mode has no agent host at all.
            entry.data.get(CONF_HOST),
        ),
    )


def async_unload_scan(hass: HomeAssistant) -> None:
    """Unregister the scan services. Platform unload is the top level's job."""
    async_unregister_services(hass)


async def async_remove_scan_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Forget the stored inventory when the merged entry itself is removed.

    Only on REMOVAL, never on unload. An unload happens on every restart and
    every reload; deleting the inventory there would destroy `first_seen` for
    the whole network on a routine restart, and no amount of rescanning brings
    it back.
    """
    if entry.data.get(CONF_MODE) == MODE_LOCAL:
        await InventoryStore(hass, entry.entry_id).async_remove()
    # A repair outlives the coordinator that raised it, and the issue registry
    # is not cleared by removing an entry. One about targets nobody scans any
    # more is a warning that cannot be acted on or dismissed by fixing
    # anything -- so it goes with the subject it is about.
    ir.async_delete_issue(hass, DOMAIN, empty_targets_issue_id(entry.entry_id))


async def async_remove_scan_device(
    hass: HomeAssistant,
    entry: ConfigEntry,
    device: DeviceEntry,
    coordinator: NetworkInventoryCoordinator,
) -> bool:
    """Allow deleting an endpoint that is no longer on the network.

    ENDPOINTS ARE NEVER DELETED AUTOMATICALLY. A host that stops answering has
    two possible explanations -- it left, or it is switched off -- and the
    scanner cannot tell them apart. Removing its device on the first missed
    scan would silently destroy its history, and re-creating it on return
    would make "when did this first appear" meaningless. So a departed
    endpoint's entities go UNAVAILABLE and stay, and the decision to forget it
    is left to the person who knows which of the two happened.

    The scanner device itself is refused: deleting it would strand every
    endpoint that points at it as its `via_device_id`.
    """
    ours = {i[1] for i in device.identifiers if i[0] == DOMAIN}
    if entry.entry_id in ours:
        return False

    live = set(coordinator.data.endpoints) if coordinator.data else set()
    # Refuse while the endpoint is still being seen -- it would reappear on the
    # next refresh, which reads as the delete having silently failed.
    return not (ours & live)
