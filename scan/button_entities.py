"""Buttons: start a scan on demand.

IN AGENT MODE A PRESS IS A REQUEST, NOT A RESULT. The agent queues the scan
and answers 202; the scan itself starts moments later and runs for as long as
it runs. Nothing waits for it and nothing reports success -- pressing means
"asked", and `scan in progress` on the matching switch is where you see that
it actually started.

IN LOCAL MODE THE PRESS AWAITS THE SCAN, because there is no queue to hand it
to: `async_run_custom_scan` runs nmap in this process and returns when it is
done. That has always been true of the standard and deep profile buttons here,
and it is true of the per-endpoint button below. The service call stays open
for the length of the scan, which for a deep profile is all 65,535 ports; the
alternative is reporting a scan complete before it has read a single one.

THE PROFILE LIST IS PINNED, NOT DISCOVERED. It mirrors the agent's own
allowlist. Offering a button the agent will reject is worse than offering
none: a control that looks live and does nothing teaches people the whole
surface is unreliable.
"""

from __future__ import annotations

from homeassistant.components.button import ButtonEntity, ButtonEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .api import NetworkInventoryError
from .const import CONF_HOST, CONF_MODE, MODE_LOCAL, PROFILES
from .entity import EndpointEntity, ScannerEntity
from .helpers import schedule_followup_refresh
from .options import PROFILES as OPTION_PROFILES, InvalidScanRequest
from .scanner import ScanError

# EVERY WAY A SCAN REQUEST CAN LEGITIMATELY FAIL, in both modes. Caught as one
# tuple rather than as a bare `Exception` so a genuine programming error still
# surfaces as a traceback instead of being reported to the user as a scan that
# could not be queued.
SCAN_REQUEST_ERRORS = (NetworkInventoryError, ScanError, InvalidScanRequest)


def setup_scan_buttons(
    hass: HomeAssistant,
    entry: ConfigEntry,
    coordinator,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up one scan button per profile, and a deep-scan button per endpoint.

    MERGE NOTE: coordinator now passed in, see entities.py's setup_scan_sensors
    docstring.
    """
    async_add_entities(
        ScanButton(
            coordinator,
            entry.entry_id,
            entry.title,
            # .get, not [] -- local mode has no agent host at all.
            entry.data.get(CONF_HOST),
            ButtonEntityDescription(
                key=f"scan_{profile}",
                translation_key=f"scan_{profile}",
                icon="mdi:radar",
                entity_category=EntityCategory.CONFIG,
            ),
            profile,
        )
        for profile in PROFILES
    )

    # LOCAL MODE ONLY, and not offered at all otherwise. `async_run_custom_scan`
    # is a LocalCoordinator method: the agent's v1 API has no custom-scan
    # channel, which is why `custom_scan` and `scan_device` both refuse in
    # agent mode. A per-host button on an agent entry would be a control that
    # looks live and does nothing -- the failure this module's own header is
    # written about -- so it is absent rather than present and broken, the
    # same choice the options flow makes about scope and schedule.
    if entry.data.get(CONF_MODE) != MODE_LOCAL:
        return

    # ENDPOINTS ARE DISCOVERED, NOT ENUMERATED ONCE, and `seen` is never
    # pruned -- both for the reasons `entities.setup_scan_sensors` gives: a
    # host that joins later must get its button without a reload, and one that
    # leaves keeps it (reading unavailable) rather than gaining a second copy
    # when it returns.
    seen: set[str] = set()

    @callback
    def _add_new_endpoints() -> None:
        data = coordinator.data
        if data is None:
            return
        fresh = [mac for mac in data.endpoints if mac not in seen]
        if not fresh:
            return
        seen.update(fresh)
        async_add_entities(
            DeepScanButton(
                coordinator,
                entry.entry_id,
                mac,
                ButtonEntityDescription(
                    key="deep_scan",
                    translation_key="deep_scan",
                    icon="mdi:radar",
                    entity_category=EntityCategory.CONFIG,
                ),
            )
            for mac in fresh
        )

    _add_new_endpoints()
    entry.async_on_unload(coordinator.async_add_listener(_add_new_endpoints))


class ScanButton(ScannerEntity, ButtonEntity):
    """Ask the agent to run one scan profile now."""

    def __init__(self, coordinator, entry_id, title, host, description, profile):
        super().__init__(coordinator, entry_id, title, host, description)
        self._profile = profile

    async def async_press(self) -> None:
        """Queue the scan, then look again shortly.

        The agent's answer only says the request was accepted -- the scan is
        started by a separate privileged unit a moment later. Refreshing
        immediately would read the state from before it started, so the
        follow-up is delayed enough for the transition to have happened.
        """
        try:
            # Through the COORDINATOR, not through a client. In local mode
            # there is no client, and a control that raises AttributeError in
            # one of two supported modes is a fork wearing a method call.
            await self.coordinator.async_request_scan(self._profile)
        except SCAN_REQUEST_ERRORS as err:
            # Surfaced to the user rather than swallowed: a button that
            # silently fails is indistinguishable from one that worked.
            raise HomeAssistantError(
                f"could not queue a {self._profile} scan: {err}"
            ) from err
        schedule_followup_refresh(self.hass, self.coordinator)


class DeepScanButton(EndpointEntity, ButtonEntity):
    """Run the deep profile against this one host, now.

    WHY A BUTTON AND NOT JUST THE SERVICE. `cyber_estate.custom_scan` and
    `scan_device` can already do this, but only from Developer Tools with the
    right option boxes ticked. The question "what is actually open on THAT
    box" is asked while looking at that box's device page, and the control
    belongs where the question is asked.

    THE DEEP PROFILE, NOT A NEW ONE. `options.PROFILES["deep"]` is the same
    option set the scanner's own Scan now (deep) button uses, so the two
    cannot drift into meaning different things.

    AN ON-DEMAND SCAN NEVER PRUNES -- `async_run_custom_scan` passes
    `stale_days=None` (GH-31). Aiming a scan at one host must not age every
    other record toward deletion.
    """

    async def async_press(self) -> None:
        """Scan this host and fold the result in.

        AWAITS THE SCAN, like the scanner device's own standard and deep
        buttons, which reach the same `async_run_custom_scan`. All 65,535
        ports takes as long as it takes and the press holds the service call
        open for it; a second, different pattern for the same action would be
        worse than the wait, and the alternative -- returning immediately --
        would report a scan as done before it had read a single port.
        """
        host = self._host
        address = (host or {}).get("ip")
        if not address:
            # MEASURED, NOT ASSUMED. Without a current address there is
            # nothing to aim at, and scanning the last known one would scan
            # whatever holds that address now -- a different machine.
            raise HomeAssistantError(
                "this host has no current address in the inventory, so there "
                "is nothing to scan; wait for the next sweep to place it"
            )

        try:
            await self.coordinator.async_run_custom_scan(
                targets=[address],
                option_keys=list(OPTION_PROFILES["deep"]),
                label=f"deep scan {address}",
            )
        except SCAN_REQUEST_ERRORS as err:
            # Surfaced, never swallowed -- the same rule ScanButton follows.
            # A deep scan without the NSE tree refuses HERE, before the
            # scanner lock, with a message naming the missing datadir; that
            # reason is the whole value of the failure.
            raise HomeAssistantError(
                f"could not deep scan {address}: {err}"
            ) from err
