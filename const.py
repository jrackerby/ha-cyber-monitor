"""Top-level constants for cyber_estate.

Merges three previously-standalone integrations -- estate_feeds
(CISA/CDC RSS), nvd_estate (NVD CVE + CISA KEV matching), network_inventory
(nmap scanning) -- under one manifest, one config entry, one domain. Each
subsystem's own business logic (feed parsing, CPE matching, nmap invocation,
SSH probing) moved nearly verbatim into feeds/, cve/ and scan/ subpackages;
only the integration-plumbing layer (manifest, __init__, config_flow,
platform setup) was rewritten to combine three coordinators under one entry.

entry.runtime_data on the merged entry is a dict, not one coordinator:
    {"feeds": EstateFeedsCoordinator, "cve": NvdEstateCoordinator,
     "scan": NetworkInventoryCoordinator}

ENTITY IDS ARE PRESERVED ACROSS THE MERGE, DELIBERATELY. estate_feeds pins
sensor.cdc_domestic_alerts / sensor.cisa_advisories (three downstream
template blocks in packages/*.yaml read them by name); nvd_estate's five
sensor.nvd_estate_* entities are read directly by www/cyber-alerts-card.js.
Neither needed to change for the merge to work, so neither did -- see
feeds/entities.py and cve/entities.py, which still explicitly assign
self.entity_id rather than let it derive from the new domain.

THE SERVICE DOMAIN DID CHANGE, UNAVOIDABLY: network_inventory.custom_scan /
scan_device are now cyber_estate.custom_scan / cyber_estate.scan_device,
because a service lives under its OWNING integration's domain and that
domain is no longer network_inventory. www/network-scan-card.js was updated
to match.
"""

from __future__ import annotations

from homeassistant.const import Platform

DOMAIN = "cyber_estate"

PLATFORMS: list[Platform] = [
    Platform.BINARY_SENSOR,
    Platform.BUTTON,
    Platform.SENSOR,
    Platform.SWITCH,
]
