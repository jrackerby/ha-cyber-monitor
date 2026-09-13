"""Binary sensor platform: the two security flags an automation triggers on.

THE FLAGS ARE A VIEW, NOT THE MECHANISM. Every decision -- when a finding is
confirmed, when it may clear, how long a state is held, how often the bus
hears of it -- is the `AlertMonitor`'s (alerts.py), which runs whether or not
either of these entities is enabled. Disable one and the events keep firing;
what stops is the display.

TWO FLAGS, ON THE TWO DEVICES THAT OWN THEIR FINDINGS: `unknown_host_present`
on the scanner, `actionable_vulnerability` on the NVD device. Not one rolled-up
"security problem" flag: an automation blocking a MAC and one opening a
patching ticket are different actions on different evidence, and a single
flag would make both fire on either.

AVAILABILITY FOLLOWS THE OWNING COUNT SENSOR. `unknown_host_present` goes
unavailable with the scan coordinator, for the reason `unknown_hosts` does: an
agent that cannot be reached did not measure the network, and `off` there
would read as "nothing unknown" at exactly the moment nobody can tell.
`actionable_vulnerability` is always available, as every cve entity is -- the
monitor never observes an unread, so the flag simply holds its last
confirmed value while NVD is unreachable, and `last_observed` says how old
that is.
"""

from __future__ import annotations

from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .alerts import FLAG_UNKNOWN_HOSTS, FLAG_VULNERABILITIES, AlertMonitor
from .const import DOMAIN
from .cve.const import CVE_NS
from .runtime import alert_monitor_of, scan_coordinator_of
from .scan.const import CONF_HOST
from .scan.entity import scanner_device_info


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    monitor = alert_monitor_of(entry)
    scan = scan_coordinator_of(entry)
    async_add_entities(
        [
            UnknownHostPresent(monitor, scan, entry),
            ActionableVulnerability(monitor, entry.runtime_data["cve"]),
        ]
    )


class _Flag(CoordinatorEntity, BinarySensorEntity):
    """Shared shape: subscribe to the monitor, read one flag off it."""

    _attr_has_entity_name = True
    _attr_device_class = BinarySensorDeviceClass.PROBLEM
    _flag: str

    def __init__(self, monitor: AlertMonitor, coordinator) -> None:
        super().__init__(coordinator)
        self._monitor = monitor

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        # THE MONITOR, NOT THE COORDINATOR, DRIVES THE WRITE. A hold expiring
        # flips the flag with no coordinator refresh behind it, and only the
        # monitor knows when that happens.
        self.async_on_remove(self._monitor.async_add_listener(self._monitor_moved))

    @callback
    def _monitor_moved(self) -> None:
        self.async_write_ha_state()

    @property
    def is_on(self) -> bool:
        return self._monitor.is_on(self._flag)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return self._monitor.attributes(self._flag)


class UnknownHostPresent(_Flag):
    """On while at least one confirmed unaccounted-for host is on the network."""

    _flag = FLAG_UNKNOWN_HOSTS
    _attr_translation_key = "unknown_host_present"
    _attr_icon = "mdi:lan-disconnect"

    def __init__(self, monitor: AlertMonitor, coordinator, entry: ConfigEntry) -> None:
        super().__init__(monitor, coordinator)
        self._attr_unique_id = f"{entry.entry_id}_unknown_host_present"
        self._attr_device_info = scanner_device_info(
            entry.entry_id, entry.title, entry.data.get(CONF_HOST)
        )


class ActionableVulnerability(_Flag):
    """On while the CVE join reports at least one AFFECTED finding."""

    _flag = FLAG_VULNERABILITIES
    _attr_translation_key = "actionable_vulnerability"
    _attr_icon = "mdi:shield-alert"

    def __init__(self, monitor: AlertMonitor, coordinator) -> None:
        super().__init__(monitor, coordinator)
        self._attr_unique_id = f"{CVE_NS}_actionable_vulnerability"

    @property
    def device_info(self) -> DeviceInfo:
        # The same device cve/entities.py builds, so the flag lands beside the
        # count it debounces rather than on a device of its own.
        return DeviceInfo(
            identifiers={(CVE_NS, CVE_NS)},
            name="NVD Vulnerabilities",
            manufacturer="Cyber Monitor",
            model="Vulnerability applicability",
            entry_type="service",
        )

    @property
    def available(self) -> bool:
        return True
