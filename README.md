<p align="center">
  <img src="brand/logo.png" alt="HA Cyber Monitor" width="300">
</p>

# Cyber Monitor

Answers one question in Home Assistant: **is anything on this network a problem
right now** — an unfamiliar device, a known vulnerability in something you are
running, or a published advisory that applies to you.

It does that by joining three things that are normally separate:

1. **What is actually on the network.** Scheduled `nmap` sweeps of the subnets
   you name, building an inventory that remembers when each device was
   `first_seen`. Anything new and unacknowledged is an unknown host.
2. **What is known to be wrong with it.** NVD (CVE) lookups against that
   inventory, so the vulnerability data is about the services actually
   answering on your network rather than a generic feed.
3. **What is being published.** Security advisory and alert feeds, parsed
   offline from bytes this integration fetched itself.

Each part is useful alone; the point of having them in one component is step 2,
which needs step 1's inventory to mean anything.

> **The domain is `cyber_estate`, not `cyber_monitor`.** The repository and the
> component do not share a name, and the domain is the one that cannot change:
> Home Assistant dispatches a config entry on its domain, so renaming one is an
> offline registry rewrite that orphans every entity id rather than a rename.
> Actions, entity ids and the install path therefore all read `cyber_estate`.

## One entry, three coordinators

The three halves share a single config entry, and that has a consequence worth
knowing before you file a bug:

- **feeds** and **cve** coordinators *never* raise. An unreadable source is a
  disposition the entities report, not a setup failure — a monitor that
  disappears with its subject cannot report the subject down.
- **scan** *can* raise `ConfigEntryNotReady`, because it needs the `nmap`
  binary present.

So a scan failure retries the **whole** entry, including the two halves that
would have succeeded. One entry has one setup lifecycle by construction; if
`nmap` is missing, expect the feed and CVE entities to go with it.

## What it creates

Platforms: `binary_sensor`, `button`, `sensor`, `switch`.

- **feeds** — advisory/alert feeds, timezone-correct. `feeds/feedparse.py`
  resolves feed timezone *abbreviations* from an explicit table rather than by
  matching the host's local zone, which is what `dateutil` does by default and
  which silently mis-orders entries on any host outside the feed's zone.
- **cve** — NVD lookups against the inventory the scanner builds.
- **scan** — nmap sweeps, unknown-host detection, MAC acknowledgement.
- **alerts** — two debounced flags, `binary_sensor.<scanner>_unknown_host_present`
  and `binary_sensor.nvd_vulnerabilities_actionable_vulnerability`, and the
  `cyber_estate_event` stream behind them (`unknown_host_detected` /
  `_cleared`, `vulnerability_actionable` / `_cleared`). A finding is confirmed
  after N consecutive scans and cleared after M, a flag holds for a minimum
  time once it changes, and events are capped per hour per type. Nothing is
  suppressed silently: deferred flips and dropped events are counted on the
  flag's attributes. Defensive-action automation templates for all of it are
  in [`docs/automations.md`](docs/automations.md).

## Configuration

Config flow, single entry. Asks for the scan targets and the NVD API key;
optionally an exclude list, a data directory, stale-host thresholds, SSH
credentials for authenticated collection, TLS/verification flags, and a list of
already-acknowledged MACs.

**Options** (*Configure* on the entry) edit what is safe to change while it
runs, one concern per step: the networks to scan and the addresses to leave
alone, how often each local sweep runs, the acknowledged MACs, and when a
finding becomes an alert (scans to confirm and to clear, minimum hold, events
per hour). Each step
saves on its own, takes effect on the scanner's next tick, and neither reloads
the integration nor touches the scan history — so a subnet can be added without
losing the date every device was first seen.

Scan scope and the sweep clocks apply to LOCAL mode only. With a separate
scanner agent, the targets live in that host's own `scan.sh` and the schedule in
its `nmap-scan@<profile>.timer` units; the agent's v1 API exposes no interval,
so those steps are not offered rather than offered and ignored.

Requires `feedparser` and `python-dateutil`, declared in the manifest and
installed by Home Assistant.

## Actions

Both are local-mode only. With a separate scanner agent the v1 API exposes no
custom-scan channel, so they refuse rather than appearing to work.

- **`cyber_estate.custom_scan`** — sweep now, choosing what to look for.
  `targets` is optional and defaults to everything the entry is configured for;
  the rest are toggles that each cost time (service and version detection, OS
  identification, all 65,535 ports, safe detection scripts, common UDP ports,
  scanning addresses that ignore ping, traceroute). `fast_timing` and
  `thorough_timing` are mutually exclusive.
- **`cyber_estate.scan_device`** — rescan one device at its current address,
  with service detection on by default. This is the answer for phones and
  tablets, which are asleep when the scheduled sweep runs and so never get
  service data from it.

Every field is described in `services.yaml`, which is what Home Assistant
renders in Developer Tools and the automation editor.

## Removal

Delete the entry under *Settings → Devices & Services*, then remove the
integration from HACS.

**Deleting the entry destroys the scan inventory.** That store is what holds
`first_seen` for every device on the network, and `async_remove_entry` drops it
with the entry — deliberately, since removing the subject is how you erase the
subject. The recorder keeps only the sensor values that were published, not the
rows behind them, so it cannot reconstruct the store. If you want that history,
export it before removing the entry. This is also why adding a subnet goes
through *Configure* rather than a rebuild.

Individual discovered devices can be removed from the device page; one that is
still being seen on the network refuses, because it would reappear on the next
sweep.

## Install

**Via HACS.** HACS → ⋮ → *Custom repositories* → `https://github.com/jrackerby/ha-cyber-monitor`,
category **Integration**. Install, restart Home Assistant, then add it under
*Settings → Devices & Services → Add Integration → "Cyber Monitor"*.

The integration lives at the repository **root**, not under
`custom_components/`. `hacs.json` declares `content_in_root: true`, so HACS
copies the root into `/config/custom_components/cyber_estate/`.

## Development

Issues and feature requests: **[jrackerby/ha-cyber-monitor/issues](https://github.com/jrackerby/ha-cyber-monitor/issues)**.

CI runs [hassfest](https://developers.home-assistant.io/blog/2020/04/16/hassfest)
and HACS validation on every push. `validate.yml` stages the repo into the
layout hassfest scans (`jrackerby/HA` `tools/work_docs/TOOLS.md` carries why);
the repo itself stays root-layout because `hacs.json` declares
`content_in_root: true`.

Pushing a `manifest.json` whose `version` has changed tags and publishes a
release automatically — that is the only supported way to cut one.
