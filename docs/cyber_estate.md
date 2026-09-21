# cyber_estate

> **Front-end consumers below are HISTORICAL.** Every `www/*.js` card and
> every `dashboards/*.yaml` board this document names was deleted — the card
> fleet and its 54 `/local/` resource registrations by GH-564, the 41 dead
> board files and the card-era tooling by GH-575. Verified live: the Lovelace
> resource registry holds no `/local/` entry and `lovelace/dashboards/list`
> returns `[]`.
>
> What that does and does not invalidate: **the entity, platform and
> resolution content is unaffected** and is still the reference for this
> integration. Only the consumer claims are stale, and they are stale in one
> direction — a card named here as a consumer no longer exists, so "who reads
> this entity" reads as *nobody in this repo* until a dashboard app claims it.
> Those apps live in their own repos (CLAUDE.md §5) and are not greppable from
> here, so absence of a consumer in this document is not evidence there is
> none. A "no consumer found" conclusion reached by grepping `www/` or
> `dashboards/` still holds; the directories it names simply no longer exist.

Siblings: [`cyber_estate_abstract.md`](cyber_estate_abstract.md)
(plain-language summary, no jargon) ·
[`cyber_estate_process_flow.md`](cyber_estate_process_flow.md) (control flow
/ execution order) · [`cyber_estate_data_flow.md`](cyber_estate_data_flow.md)
(data lineage) · [`cyber_estate_architecture.md`](cyber_estate_architecture.md)
(static structure) ·
[`cyber_estate_patent_disclosure.md`](cyber_estate_patent_disclosure.md)
(novelty assessment).

`custom_components/cyber_estate` — version 1.0.0 (`manifest.json`). KAN-344
merged three formerly-standalone integrations — `estate_feeds` (CDC/CISA RSS
monitoring), `nvd_estate` (CISA KEV + NVD CVE matching against installed
software versions), `network_inventory` (nmap/SSH network scanning) — under
one manifest, one domain, one config entry, as `feeds/`, `cve/` and `scan/`
subpackages. Each subsystem's own business logic moved nearly verbatim;
only the integration-plumbing layer (manifest, `__init__.py`,
`config_flow.py`, platform dispatch) was rewritten to combine three
coordinators under one entry. Source of truth for anything below is
`custom_components/cyber_estate/` itself; this file is a reader's map onto
that code, not a replacement for it — if the two disagree, the code is
right and this file is stale.

## 1. Purpose

Three independent security-monitoring functions sharing one config entry
because they were judged to belong to the same operational concern (KAN-344)
rather than because they share logic: **feeds/** keeps a bounded, honestly-
dispositioned mirror of CDC and CISA advisory RSS feeds so a dead feed reads
as dead rather than as a silent all-clear; **cve/** joins the CISA Known
Exploited Vulnerabilities catalog and NVD's CVE database against the exact
software version each device in the house's device registry actually runs,
so a vulnerability is only flagged when it genuinely applies; **scan/**
discovers every host on the LAN by nmap (run locally or via a remote agent)
and answers "what's here, what's running, is anything unaccounted for,
can Home Assistant itself SSH in." None of the three subsystems calls into
another's code; they are combined for one setup lifecycle and one
config-entry UI, not for shared logic. See
`cyber_estate_architecture.md` for the full shared-vs-separate breakdown.

## 2. Requirements to run

- `manifest.json`: `dependencies: []`, `requirements: ["feedparser==6.0.11",
  "python-dateutil>=2.8.2"]`. `integration_type: service`, `iot_class:
  local_polling`, `single_config_entry: true` — **one entry for all three
  subsystems**, added via **Settings → Devices & Services → Add Integration
  → Cyber Estate**.
- **Config flow is sequential, not branched**: an NVD API key step
  (`async_step_user`, validated against NVD live before acceptance — an
  unauthenticated request still succeeds at a lower rate limit, so a typo'd
  key does not announce itself until it silently rate-limits hours later)
  is always first, then a scan-mode menu (`async_step_scan_mode`) offering
  **local** (nmap runs inside the HA container) or **agent** (HA polls a
  separate nmap-scanner process over HTTP). Both halves' validation is
  preserved from the standalone integrations' own flows; only the
  sequencing and the final `async_create_entry` are new.
  - **Local mode fields**: `targets` (comma-separated addresses/CIDRs,
    required), `exclude`, `datadir` (nmap NSE script-engine tree — HA's
    bundled nmap ships without one; blank disables service/version
    detection), `stale_days` (default 30, floor 1 — edited afterwards by
    RECONFIGURE, which writes `entry.data` and reloads, never by the options
    flow; a stored value under the floor resolves to the default rather than
    saturating, see `settings.resolve_stale_days`), `ssh_probe_enabled`
    (default on), `ssh_key` (default `/config/.ssh/kiosk_key`),
    `ssh_users` (default `kiosk, root`). Validated at submit time
    (`validate_target()` per address, `find_nmap()` checked live) — a
    target nmap would refuse is rejected while the form is still open.
  - **Agent mode fields**: `host`, `port` (default 8765), `token`,
    `use_tls`, `verify_ssl`. Verified live against the agent
    (`NetworkInventoryClient.async_verify()`) before the entry is created.
- **Options flow is scan-only**: one field, `acknowledged_macs`
  (`CyberEstateOptionsFlow`), a comma-separated MAC list an operator
  affirms as accounted-for. Deliberately does not touch scan mode or the
  NVD key — a wholesale-rewrite options flow risks the "resubmit
  everything or lose a field" trap this codebase has hit elsewhere. Read
  live by `scan/coordinator.py`'s `_acknowledged_macs()` on every refresh,
  so acknowledging a host takes effect on the next tick, no reload
  required — `_async_options_updated` (top-level `__init__.py`) also fires
  an explicit `scan` coordinator refresh on save, rather than waiting for
  the ordinary poll.
- **Reauth is NVD-API-key only.** `cve/coordinator.py` calls
  `entry.async_start_reauth(hass)` directly on a 401/403 rather than
  raising `ConfigEntryAuthFailed` (which would take every `cve/` entity
  unavailable); `async_step_reauth_confirm` updates only `CONF_API_KEY` via
  `data_updates`, which merges into `entry.data` rather than replacing it —
  a reauth never touches the scan half of the entry.
- **The one merge-introduced behavior change**: because all three
  subsystems now share one config entry, a `scan/`-only setup failure
  (`ConfigEntryNotReady`, raised only for a missing nmap binary in local
  mode) retries the **whole entry**, including the always-succeeding
  `feeds/` and `cve/` halves. Stated directly in top-level `__init__.py`'s
  module docstring as an accepted, deliberate widening of blast radius —
  "a merged entry has one setup lifecycle by construction."
- **No restart needed** to pick up a new device in the registry (`cve/`
  re-walks it every 6h refresh), a newly-discovered network host or
  service (`scan/` creates entities dynamically, see
  `cyber_estate_architecture.md`), or an acknowledged MAC (options flow
  triggers an explicit refresh). **A restart is required** after editing
  `custom_components/` itself (TOOLS.md: `homeassistant.reload_core_config`
  does not re-import a custom component).
- **Local-mode scan requirements outside this repo's control**: the `nmap`
  binary must be on `PATH` inside the HA container (checked at setup,
  executor-blocking `shutil.which`); service/version detection additionally
  needs an NSE tree at the configured `datadir` (default
  `/config/nmap-data`) because HA's bundled nmap ships without one — its
  absence is logged loudly but is not fatal (port scanning still works).
  SSH probing additionally needs the real `ssh` client binary on `PATH`.

## 3. Process / dataflow

One paragraph, links to the diagrams for the rest. Setup runs the three
subsystems' first refreshes **sequentially** (feeds, then cve, then scan)
inside one coroutine; only `scan/`'s local-mode setup can raise. After
setup, the three coordinators run on three independent clocks — `feeds/`
every 3600s, `cve/` every 6 hours, `scan/` either a 10-minute agent poll or
a 5-minute local-mode tick that itself only *checks* whether a 1-hour
discovery sweep or a 24-hour service sweep is due, launching at most one
per tick as a non-blocking background task. See
`cyber_estate_process_flow.md` for the full per-subsystem execution
sequence including every raise/no-raise branch, and
`cyber_estate_data_flow.md` for how a value moves from an external source
(CDC/CISA RSS, NVD/KEV APIs, nmap XML or the agent's JSON) through each
subsystem's pure transform layer (`feeds/feedparse.py`, `cve/cpe.py`,
`scan/join.py`, `scan/parse.py`, `scan/services_view.py` — five
independent HA-free modules, one per subsystem's core decision, none
shared) to the entities and services listed below.

## 4. Reference tables

### 4.1 feeds/ entities

One device, "Estate Feeds" (`estate_feeds` local namespace). Entity ids are
**explicitly pinned**, not derived from `_attr_has_entity_name`, because
three downstream template blocks read them by exact id — see
`cyber_estate_data_flow.md`.

| Entity | Purpose | Key attributes |
|---|---|---|
| `sensor.cdc_domestic_alerts` | CDC Domestic Alerts RSS mirror | `entries` (list of dicts: title/link/published/summary), `latest_key`, `disposition` (`ok`/`unreachable`/`http_error`/`unparsed`), `detail`, `stale`, `last_success`, `http_status`, `bozo`, `unparsed_dates`, `feed_url` |
| `sensor.cisa_advisories` | CISA Cybersecurity Advisories RSS mirror | Same shape as above (title/link/published only — no `summary` in this feed's `inclusions`) |

Both entities' `native_value` is the entry count when `disposition == ok`,
else `None` (never a plausible zero). Both override `available` to `True`
unconditionally — health is carried in `disposition`, never in entity
availability.

### 4.2 cve/ entities

One device, "NVD Estate" (`nvd_estate` local namespace, manufacturer "El
Coronel Luz").

| Entity | Purpose | Key attributes |
|---|---|---|
| `sensor.nvd_estate_actionable_vulnerabilities` | KEV-driven, version-dispositioned actionable count — the only number meant to drive a wall alert | `counts` (by disposition), `affected` (capped list), `unknown_version` (capped list), `ransomware_linked`, `with_due_date`, `detail_capped_at`/`detail_truncated`, `generated` |
| `sensor.nvd_estate_integrity` | Whether `actionable` can be trusted — a different audience (operator), never a lower severity | state: `ok`/`degraded`/`unauthorized`/`unknown`; attrs: `sources` (per-source status dict, always present), `errors`, `truncated`, `generated` |
| `sensor.nvd_estate_unmapped_devices` | Devices carrying a version nothing checks — the coverage gap, published rather than implied | `mapped_devices`, `accepted_devices`, `unmapped_sample` (capped 15), `accepted_reasons`, `version_conflicts`, `ownership_rejected` |
| `sensor.nvd_estate_worst_disposition` | Worst disposition anywhere in the finding set | `order_worst_first` (the fixed `SEVERITY_ORDER`), `counts`, `generated` |
| `sensor.nvd_estate_recent_affected` | Recently-published CVEs (90-day window) affecting an installed version — deliberately separate from `actionable`; expected non-zero | `by_target` (product:version → cves/sampled/crit/high/unrated/worst, worst-first ordered, capped 25), `targets_queried`, `cve_device_pairs`, `critical`/`high`/`unrated`, `comparator_disagreements`, `detail_truncated` |

`build_cve_sensors()` returns **five** sensor instances
(`NvdActionableSensor`, `NvdIntegritySensor`, `NvdCoverageSensor`,
`NvdRollupSensor`, `NvdRecentAffectedSensor`) — `cve/entities.py`'s own
module docstring states "FOUR SENSORS, AND THE SPLIT IS DELIBERATE" and
only describes `actionable`/`integrity`/`coverage`/`rollup` in that list.
This is a stale comment: `NvdRecentAffectedSensor` exists, is registered,
and has real consumers (`cve-card.js`, `network-security-card.js`) — the
docstring was not updated when it was added. All five override `available`
to `True` unconditionally; `actionable` is `None`, never `0`, whenever a
source did not answer.

### 4.3 scan/ entities and services

**Two device populations**, never conflated: one scanner device (per
config entry) and one device per discovered network endpoint, created
dynamically as hosts are seen.

Scanner-device rollup sensors (`scan/entities.py:SENSORS`):

| Entity key | Purpose | Key attributes |
|---|---|---|
| `unknown_hosts` | Scanned hosts whose MAC matches neither the device registry nor the acknowledged-MACs list | `hosts` (capped 25), `detail_capped_at`/`detail_truncated`, `matched`, `unjoinable_no_mac`, `acknowledged_count`, `acknowledged` (capped 25) |
| `hosts_tracked` | Total hosts in the inventory | — |
| `hosts_up` | Hosts currently answering | — |
| `exposed_services` | Total open-port count across the estate | `hosts_with_port_data`, `hosts_total` |
| `never_port_scanned` | Hosts whose ports have never been enumerated — the instrument's blind spot, published as a first-class number | — |
| `service_census` | Distinct service count | Full `census()` payload: `services{}` (per-service hosts/ports/versions), `hosts_port_scanned`, `hosts_never_port_scanned`, `coverage_pct` |
| `last_scan` | Timestamp of the most recent sweep of any kind | — |
| `last_port_scan` | Timestamp of the most recent sweep that actually enumerated ports — a deliberately separate clock from `last_scan` | — |

Per-endpoint sensors (`scan/entities.py:ENDPOINT_SENSORS`, one set per
discovered MAC): `ip_address`, `operating_system` (`Undetermined`
sentinel, never blank), `last_seen`, `open_ports` (count, or `None` if
never port-scanned — never a false zero), `last_port_scan`. Plus, per
host, one `SshAccessSensor` (`authorized`/`refused`/`host_key_changed`/
`unreachable`/`no_ssh`/`never_scanned`) and one `ServiceSensor` per
distinct service ever observed open on that host (entity id ends in the
service name, e.g. `sensor.pi4kiosk04_ssh`; state
`open`/`closed`/`never_scanned`; created dynamically, **never removed**
once a service is first seen — its closure is itself a fact worth keeping
and alerting on).

Switches and buttons (scanner device, one set per profile in `PROFILES =
("discovery", "standard", "deep")`): `ScheduleSwitch` (`schedule_<profile>`
— whether that profile's timer is installed/enabled, not whether a scan is
currently running) and `ScanButton` (`scan_<profile>` — fire a scan now;
a press is a request, not a result).

Services (registered under the `cyber_estate` domain, local mode only):

| Service | Purpose | Notes |
|---|---|---|
| `cyber_estate.custom_scan` | Run a scan now with plain-English checkboxes | Fields generated 1:1 from `scan/options.py`'s `SCAN_OPTIONS` vocabulary — same list drives `services.yaml`, Developer Tools, the automation editor, and `network-scan-card.js`; `tools/test_network_inventory_services.py` asserts the two sides match |
| `cyber_estate.scan_device` | Rescan one device now, resolved by device picker to its current live address | Answers the 03:15 blind spot — a device asleep during the nightly sweep can be scanned on demand without anyone looking up its current DHCP lease |

Both services return a response (`SupportsResponse.OPTIONAL`): `did`
(plain-English summary), `cost`, `targets`, `options`, `hosts_seen`,
`seconds`, `complete` (always reported, even on a truncated scan).

**`services_view.py` is not an HTTP view** despite the name — no
`HomeAssistantView` subclass, no route registration anywhere in this
subpackage. It is a pure data-shaping module (three-state service
readings, the estate-wide `census()` rollup) consumed internally by
`coordinator.py`, `entities.py`, and `ssh_probe.py`. Worth flagging as a
naming trap for a future reader expecting an HTTP surface.

## 5. LAW.md's cyber-severity ruling, checked against current code

`tools/work_docs/LAW.md` §3 states: "CYBER NEVER CO-MINGLES WITH PHYSICAL
on a house panel... cyber rolls up on `cyber-alerts-card` by the same 0-7 ->
Normal/Elevated/Critical bands." Verified this session against
`www/cyber-alerts-card.js` directly:

- **The separation claim is accurate and enforced.** No `cyber_estate`
  entity is read by `sensor.home_threat_posture` or by `household_state`'s
  `SOURCES` registry (confirmed by reading `household_state`'s own
  `const.py` this session as part of the prior integration in this
  documentation batch) — cybersecurity findings genuinely never reach a
  physical-threat surface.
- **The 0-7 band claim is accurate but the mechanism is narrower and more
  local than the ruling's wording implies.** The rollup exists, and its
  bands are literally 0 Normal / 1-4 Elevated / 5-7 Critical (verified in
  `cyber-alerts-card.js`'s own v18 header comment) — but it is computed
  entirely **client-side**, in one JavaScript function
  (`_cyberRollup(activeRows)`), from exactly **two** of the card's rows:
  KEV (Actionable) and CISA (Estate). It is not an entity, not a template
  sensor, not recorded, and not trendable — the card's own v18 comment
  states this cost as a deliberate trade for "one severity ladder instead
  of two," and says explicitly that if it ever needs to be an entity, "the
  ladders move into a component and the card reads it back — never a
  Jinja copy of what is below."
- **`scan/` (the network-inventory subsystem) plays no role in this
  rollup at all.** Grepping `www/cyber-alerts-card.js` for any `scan/`
  entity id (`unknown_hosts`, `hosts_tracked`, etc.) returns nothing — only
  `feeds/` (via the `cisa_estate_7d` downstream template) and `cve/` (via
  `nvd_estate_actionable_vulnerabilities`/`nvd_estate_integrity`) feed the
  0-7 rollup. A reader taking LAW's summary literally — "cyber rolls up by
  the 0-7 bands" — could reasonably assume that includes the network-scan
  findings; it does not. Whether an unaccounted-for host or a closed SSH
  channel should ever contribute to this rollup is outside this doc's
  scope to decide; it is simply not wired today.
- **A third row (`cyber`, reading `sensor.cis_cyber_threat_level`) existed
  through v20 and was dropped in v21 (KAN-345)** for having no documented
  purpose and no consumer anywhere in the estate outside the card itself —
  the same "number that looks like a signal" defect the card's own v6
  header names for an earlier raw-CISA-count row it also removed. Current
  live state is two rows, not three.

## 6. Failure modes — by design, not by omission

| Situation | What happens | Why |
|---|---|---|
| feeds/: upstream RSS unreachable, HTTP error, or unparseable | `disposition` = `unreachable`/`http_error`/`unparsed`; serves the last good cached record marked `stale: True`, `count: None` | A 404 through the retired feedparser platform returned a clean `entries == []` for weeks (KAN-215); this is the specific defect the rewrite exists to remove |
| feeds/: coordinator's own fetch logic throws | Caught inside `_fetch_one`/`gather`; never raises `UpdateFailed` | Same RULE 1 as `household_state` — raising takes every entity unavailable and its attributes vanish |
| cve/: no devices match `ASSET_RULES` | `sources.nvd = "no_assets"`, logged as a config problem, never an all-clear | An empty asset list is a setup defect, not "nothing to report" |
| cve/: NVD returns 401/403 | `sources.nvd = "unauthorized"`, `entry.async_start_reauth()` fires once; counts from that partial run are discarded (`actionable = None`) | `ConfigEntryAuthFailed` would take every `cve/` entity unavailable and hide the reason at the moment it matters most |
| cve/: a version cannot be parsed, or a CPE range bound cannot be parsed | `disposition = UNKNOWN_VERSION`, never `PATCHED` | `cpe.py`'s central, asymmetric rule: "patched" licenses inaction and gets the stricter standard — every undecidable path returns unknown |
| cve/: a device record is a "ghost" (registry split leaves a fragment owned by an integration that doesn't understand its own inherited version string) | Excluded via `owner_domain` check, reported in `ownership_rejected` with the reason named | Measured live: a UniFi-owned fragment of a kiosk Pi put 425 CVEs / 44 critical on the board against a Chromium build installed nowhere |
| cve/: a CVE's CPE node is `vulnerable: false` (a platform the vulnerable product runs on, not the vulnerable product itself) | Node skipped entirely by `nodes_for()` | Caught by `tools/nvd_probe.py --dryrun` before deploy: ignoring this flag reported the estate's Linux kernels AFFECTED by a Chromium V8 bug |
| scan/ (local): nmap binary not found at setup | `ConfigEntryNotReady` — retries the **whole cyber_estate entry** | A merged entry has one setup lifecycle; accepted as the one behavior change the KAN-344 merge introduced |
| scan/ (local): NSE tree (`datadir`) missing or absent | Not fatal — logged loudly, `datadir` set to `None`, port scanning still works, service/version detection unavailable | Distinct severity from a missing nmap binary; the failure must be visible on every subsequent `-sV` attempt, never silently absorbed |
| scan/ (local): `service_versions`/`default_scripts` requested without a usable `datadir` | `ScanError` raised **before** the scanner lock is acquired, scan refused outright | Running anyway would report "no services found" confidently and wrongly for every host scanned |
| scan/ (agent): agent unreachable, wrong token, unsupported schema version, or no scan completed yet | `UpdateFailed` — every `scan/` entity goes unavailable | An unreachable agent must never surface as an empty (zero-host) inventory, which would be a false claim about the network |
| scan/ (local): a scan times out or exits non-zero | Whatever hosts nmap emitted before being killed are kept and merged, tagged `complete=False`; caller decides how to treat it | nmap flushes partial XML on SIGTERM; the observations made are real even if the sweep didn't finish |
| scan/: a liveness-only sweep (no `<ports>` element in that scan's XML) | Previous port observation carried forward verbatim; no delta computed | Computing a delta here would report every port on every host as closed after every hourly liveness sweep |
| scan/: a host has never been port-scanned | `open_ports` = `None`, service readings = `never_scanned`, SSH access = `never_scanned` — never `closed`/`no_ssh` | A blank/closed reading for an unscanned host (37 of 78 tracked hosts, measured) is a confident wrong answer, not a cautious one |
| scan/: a host's own device record has an unreadable `last_seen` | Kept, never pruned | Deleting on an unreadable field would silently destroy history on a future parsing change |
| scan/: a host this integration itself created a device record for | Excluded from `_known_macs()` | Otherwise `unknown_hosts` decays to zero as the inventory grows — the detector reporting a clean network precisely because it has run a while, the same circularity class as KAN-294's original MQTT-ghost defect |
| scan/: an operator-acknowledged MAC (multi-NIC device, e.g. the UDM Pro answering ARP on a second interface) | Moved to a separate `acknowledged` bucket, still visible on `unknown_hosts`' own attributes, does not count toward the state | "We decided this one is fine" and "this one never appeared" must not collapse into the same zero (KAN-294) |
| scan/ (local): an operator presses **Deep scan this host** on an endpoint | The `deep` profile (`service_versions`, `all_ports`, `default_scripts`) runs against that endpoint's CURRENT address via `async_run_custom_scan`, so it merges without pruning | The control belongs where the question is asked. Not offered in agent mode at all (no custom-scan channel), refused with a reason when the host has no current address — scanning its last known one would scan whatever holds that address now — and the press awaits the scan, as the scanner's own standard/deep buttons already do (GH-36) |
| scan/: an operator deletes a discovered endpoint from its device page | Allowed when the host was not seen in the most recent scan (`InventoryView.live_endpoints`); refused while it was | Until GH-33 the guard read `endpoints`, the WHOLE persisted inventory, so it refused every endpoint the integration had ever recorded and no device could be deleted at all. `status` cannot decide it either — `merge_inventory` only touches records a scan result contains, so a departed host keeps `status: "up"` indefinitely (measured: 185 tracked, 185 "up", including a subnet deleted days earlier). `last_seen` is the only field that moves when a host is seen |
| scan/ (local): a discovery sweep fails (timeout, nmap error) | The clock AND the attempted scope are stamped, so the sweep retries on its ordinary interval rather than on the next five-minute tick | An attempt that stamped neither left `_due` true and `_scope_changed` true, re-launching forever: measured at 31 sweeps in 9.4 hours against an hourly interval, nothing merged and nothing pruned for the whole window (GH-34). `_run_service_scan` already did this; `ScanBusy` still stamps nothing, because another scan holding the lock is not a failure |
| scan/ (local): the configured scope is too large for a flat liveness timeout | `discovery_timeout_seconds` is an options key (*Configure → How often to scan*); unset, it is DERIVED from the address count of the configured targets, floored at 300s and capped at 4h. A typed value pins it and stops tracking scope | A constant 300s could never finish a `/16`, which is an ordinary answer under *Configure → Networks to scan*, so that scope failed every time forever — a constant silently contradicting the configuration, which `scan/const.py`'s own header forbids |
| scan/: a departed endpoint stops answering | Entities go unavailable and **stay** — never auto-deleted | The scanner cannot tell "left" from "switched off"; auto-deleting would destroy `first_seen`, which cannot be recovered by scanning harder |
| scan/: device-removal requested for the scanner device itself, or for an endpoint still present in the live inventory | Refused (`async_remove_scan_device` returns `False`) | Removing the scanner would strand every endpoint's `via_device`; removing a still-live endpoint would silently reappear next refresh, reading as a failed delete |
| scan/ (local): an operator presses **Scan now (discovery)** | The sweep's hosts are merged and its coverage measured exactly as a scheduled sweep's are, but the inventory is NOT pruned | A sweep somebody asked for never ages the inventory: forgetting a host destroys `first_seen`, which is unrecoverable, so it belongs to the clock that runs unattended. Until GH-31 this path merged nothing at all — it swept, stamped the discovery clock (suppressing the next scheduled sweep for a full interval) and discarded the result |
| scan/ (local): a configured target answers with no hosts across `EMPTY_TARGET_SWEEPS` consecutive **complete** sweeps | A repair issue (`empty_targets`, one per entry) names the targets and points at *Configure → Networks to scan*; the sweep itself is unaffected | Address space that no longer exists answers nothing, so the sweep succeeds and reports clean — indistinguishable from a quiet network. Measured: three deleted `192.168.x` subnets swept for a day after a VLAN migration, found only because an unrelated IPS mailed about a host enumerating dead ranges (GH-29) |
| scan/ (local): a target that cannot be measured from a scan result — a hostname, or one wholly inside the exclude list | Never counted as empty, never reported | A hostname names no address span without a resolver and an excluded range is empty by instruction; reporting either would raise a repair every sweep forever, which teaches the operator to ignore the one that matters |
| scan/ (local): `stale_days` stored below its floor, negative, or non-numeric (hand-edited `.storage`, or bounds that moved between versions) | `settings.resolve_stale_days` returns the DEFAULT, not the floor | Saturating to the 1-day floor forgets every device switched off since yesterday; a negative puts `prune`'s cutoff in the future and one sweep erases the whole inventory's `first_seen` |
| scan/: SSH probe against an unrecognized failure string | Reported as `unreachable` **with the raw message attached**, never guessed as `refused` | "The key is missing" would be a guess; the honest answer is "could not connect, here is why" |

## 7. Current consumers (as of 2026-08-23)

- **`sensor.cdc_domestic_alerts`** — live, three downstream templates:
  `sensor.cdc_domestic_24h` (`packages/global_threats.yaml`, age-based
  severity, read by `www/priority-monitoring-card.js`), plus an
  acknowledgement mechanism in the same package file. `sensor.
  cisa_advisories` — live, two downstream templates: `sensor.cisa_new_24h`
  (`packages/misc.yaml`, no further consumer — its predecessor was deleted
  2026-08-09 as dead output) and `sensor.cisa_estate_7d`
  (`packages/kev_estate.yaml`, read by `www/cyber-alerts-card.js`'s CISA
  (Estate) row).
- **`sensor.nvd_estate_actionable_vulnerabilities`** — live, exactly one
  consumer: `www/cyber-alerts-card.js`'s KEV (Actionable) row. This is the
  row that, per KAN-286, first gave the actively-exploited/version-joined
  signal any watcher at all — before v17 of that card, nothing in the
  estate read this class of finding.
- **`sensor.nvd_estate_integrity`** — live, read by `cyber-alerts-card.js`,
  `network-security-card.js`, and `cve-card.js` as the gate that keeps a
  partial/failed scan from rendering as a clean board.
- **`sensor.nvd_estate_recent_affected`** — live, read by
  `www/network-security-card.js` (CVE EXPOSURE BOARD) and `www/cve-card.js`
  (one tile per target). Deliberately never merged with `actionable` in
  either consumer.
- **`sensor.nvd_estate_unmapped_devices`** — live, read by
  `www/network-security-card.js` for the coverage/version-conflict detail.
- **`sensor.nvd_estate_worst_disposition`** — **no consumer found** in
  `www/*.js`, `packages/*.yaml`, or `dashboards/*.yaml`.
- **All `scan/` sensor entities** (`unknown_hosts`, `hosts_tracked`,
  `hosts_up`, `exposed_services`, `never_port_scanned`, `service_census`,
  every per-endpoint sensor, every `ServiceSensor`, every
  `SshAccessSensor`) — **no dashboard, automation, or template consumer
  found anywhere**, verified by grepping `packages/*.yaml`, `www/*.js`, and
  `dashboards/*.yaml` for every entity-id pattern this subsystem produces.
  `www/network-scan-card.js` is mounted on `dashboards/house-health.yaml`'s
  Operator panel, but it is a **control surface only** — it reads the
  `cyber_estate.custom_scan` service's field schema from the live service
  registry to draw its checkboxes and calls that service; it does not read
  any entity this subsystem publishes. `unknown_hosts` — the entity
  KAN-294 specifically added an acknowledged-MACs mechanism for, so it
  "cannot be driven to zero" would have a real fix — has no wall, board,
  or automation displaying it today.
- **`cyber_estate.custom_scan` / `cyber_estate.scan_device` services** —
  live, called by `www/network-scan-card.js` (Operator panel, arm-then-
  confirm control) and available to Developer Tools/automations. This
  service pair only started working again 2026-08-21 (GH-74/KAN-351): the
  card's own `DOMAIN` constant was left at the pre-merge value
  `network_inventory` for weeks after KAN-344 renamed the service domain to
  `cyber_estate`, and it kept functioning only because HA had not
  restarted since the merge and left the old domain's service registration
  live in memory — a restart would have broken it silently, with the card
  sitting on "Waiting for the ... scan service" forever, indistinguishable
  from an integration that was never set up. Confirmed fixed: the card now
  reads `hass.services['cyber_estate']`.
- **`www/cyber-alerts-card.js`'s card-local 0-7 severity rollup** — live,
  the mechanism behind LAW.md's cyber-severity ruling; see §5 above for the
  detailed trace against current code.

## 8. Open work

Query live before trusting this list — issues move. At time of writing
(2026-08-23), GitHub Issues `jrackerby/HA`:

- **KAN-294** (open) — `unknown_hosts` cannot be driven to zero for a
  multi-NIC device (the UDM Pro case). The acknowledged-MACs mechanism
  this issue asked for is already implemented and live (`GH-46`,
  committed 2026-08-22) — the issue itself remains open in the tracker
  despite the code-level fix being merged; worth reconciling.
- **KAN-299** (open) — the original per-service-inventory/SSH-reachability/
  custom-scan feature request that `scan/`'s current shape implements;
  tracks the architecture decision to run nmap from inside Home Assistant
  rather than a separate LXC.
- **#391** (open) — the umbrella "document integrations" issue this file
  and its five siblings were written to satisfy.
