# cyber_estate — process flow

Siblings: [`cyber_estate.md`](cyber_estate.md) (technical reference) ·
[`cyber_estate_data_flow.md`](cyber_estate_data_flow.md) (data lineage) ·
[`cyber_estate_architecture.md`](cyber_estate_architecture.md) (static
structure) · [`cyber_estate_abstract.md`](cyber_estate_abstract.md)
(plain-language summary) ·
[`cyber_estate_patent_disclosure.md`](cyber_estate_patent_disclosure.md)
(novelty assessment).

This diagram answers **what happens, in what order**, from a trigger to an
entity update or a scan actually running. It does not describe what data
moves or where a value originated — see `cyber_estate_data_flow.md` for
that. Verified against `__init__.py`, `feeds/coordinator.py`,
`cve/coordinator.py`, `scan/__init__.py`, `scan/coordinator.py`,
`scan/scanner.py` and `scan/scan_service.py` this session.

## Setup order, and why it matters

```mermaid
flowchart TD
    START["async_setup_entry()\ncyber_estate/__init__.py"] --> F1["1. EstateFeedsCoordinator\nasync_refresh()\n(NOT first_refresh — never raises,\nso the retry machinery is dead weight)"]
    F1 --> C1["2. NvdEstateCoordinator\nasync_config_entry_first_refresh()"]
    C1 --> S1["3. async_setup_scan()\nscan/__init__.py"]

    S1 --> MODE{"CONF_MODE?"}
    MODE -->|local| SL1["_async_setup_local()\nfind_nmap() in executor"]
    MODE -->|agent| SA1["_setup_agent()\nconstruct NetworkInventoryClient\n+ AgentCoordinator"]

    SL1 --> NMAP{"nmap binary found?"}
    NMAP -->|no| RAISE["raise ConfigEntryNotReady\n== WHOLE ENTRY RETRIES,\nincluding feeds/ and cve/\n(the one merge side-effect)"]
    NMAP -->|yes| SL2["construct NmapScanner,\nInventoryStore.async_load(),\noptionally SshProber"]
    SL2 --> SL3["LocalCoordinator constructed"]

    SA1 --> SFIRST["coordinator.async_config_entry_first_refresh()\n(both modes)"]
    SL3 --> SFIRST
    SFIRST --> SVC["async_register_services()\ncyber_estate.custom_scan,\ncyber_estate.scan_device"]

    SVC --> RTDATA["entry.runtime_data = {\n  'feeds': ..., 'cve': ..., 'scan': ...\n}"]
    RTDATA --> PLATFORMS["async_forward_entry_setups()\n-> sensor.py / switch.py / button.py\ndispatchers each resolve runtime_data"]
    PLATFORMS --> LISTENER["entry.add_update_listener()\n-> _async_options_updated\n(fires scan.async_refresh() on\nCONF_ACKNOWLEDGED_MACS change)"]

    style RAISE fill:#3a1a1a,stroke:#c0392b,color:#eee
```

Three subsystems set up **sequentially in one coroutine**, not in parallel
— `feeds` first, `cve` second, `scan` third. Only `scan/`'s setup can raise
(`ConfigEntryNotReady` for a missing nmap binary in local mode); `feeds`'s
`async_refresh()` and `cve`'s `async_config_entry_first_refresh()` are both
guaranteed non-raising by their own coordinators' internal contract (see
each subsystem's refresh cycle below).

## feeds/ — refresh cycle (every 3600s, and once at setup)

```mermaid
flowchart TD
    TRIGGER["DataUpdateCoordinator's own\nscheduled interval, OR the\none setup-time call"] --> UPDATE["EstateFeedsCoordinator._async_update_data()"]
    UPDATE --> GATHER["asyncio.gather() over both FEEDS rows\n(CDC Domestic, CISA Advisories),\nreturn_exceptions=True"]
    GATHER --> FETCH["_fetch_one() per feed,\nbounded by FETCH_TIMEOUT=15s"]

    FETCH --> STATUS{"HTTP status?"}
    STATUS -->|2xx| PARSE["project_feed()\nfeedparse.py — PURE"]
    STATUS -->|non-2xx| HTTPERR["disposition = http_error\n(the 404-as-clean-zero case\nthis integration exists to prevent)"]
    STATUS -->|timeout/conn error| UNREACHABLE["disposition = unreachable"]

    PARSE --> PARSABLE{"parsable?"}
    PARSABLE -->|yes| OK["disposition = ok\nrecord cached as _last_good[key]"]
    PARSABLE -->|no| UNPARSED["disposition = unparsed"]

    HTTPERR & UNREACHABLE & UNPARSED --> STALE["Serve _last_good[key] if any,\nmarked stale=True, count=None\n(never a false empty-list zero)"]

    OK --> ASSEMBLE["Assemble one dict,\none row per feed key"]
    STALE --> ASSEMBLE

    ASSEMBLE --> NEVERRAISE["ALWAYS returns the dict —\nno UpdateFailed, ever\n(even a bug inside gather()\nis caught and logged)"]
    NEVERRAISE --> ENTITIES["FeedSensor.native_value /\nextra_state_attributes\nread coordinator.data live"]

    style HTTPERR fill:#3a2a1a,stroke:#c98a2b,color:#eee
    style UNREACHABLE fill:#3a2a1a,stroke:#c98a2b,color:#eee
    style UNPARSED fill:#3a2a1a,stroke:#c98a2b,color:#eee
```

## cve/ — refresh cycle (every 6h)

```mermaid
flowchart TD
    TRIGGER["6h scheduled interval"] --> DISCOVER["1. _discover()\nwalk device_registry,\nclassify_device() per device\nagainst ASSET_RULES/ACCEPTED_RULES"]
    DISCOVER --> ASSETS{"any assets found?"}
    ASSETS -->|no| NOASSETS["sources.nvd = 'no_assets'\n(a config problem, not clean)"]
    ASSETS -->|yes| KEV["2. _fetch_kev()\nCISA KEV catalog,\nfiltered to KEV_VENDOR_KEYWORDS\nand a 90-day WINDOW_DAYS cutoff"]

    KEV --> KEVERR{"kev fetch ok?"}
    KEVERR -->|no| KEVFAIL["sources.kev = error,\nkev_entries = [] (continues anyway)"]
    KEVERR -->|yes| PERCVE["3. Per surviving KEV CVE id,\nsorted, spaced 0.7s apart\n(NVD_REQUEST_SPACING)"]
    KEVFAIL --> PERCVE

    PERCVE --> FETCHCVE["_fetch_cve(cve_id)"]
    FETCHCVE --> AUTHCHECK{"401/403?"}
    AUTHCHECK -->|yes| REAUTH["_maybe_start_reauth()\nentry.async_start_reauth()\n(NOT ConfigEntryAuthFailed —\nentities stay up and say why)\nBREAK: no counts from partial run"]
    AUTHCHECK -->|no| MATCH["nodes_for() per asset\n(cpe.py — PURE)\ndisposition() per asset:\nAFFECTED / PATCHED / UNKNOWN_VERSION /\nUNMONITORED / ACCEPTED"]

    MATCH --> FINDINGS["findings list assembled"]
    FINDINGS --> COUNTS["counts by disposition,\nactionable = counts[AFFECTED]\n(only when BOTH kev and nvd sources = ok;\nelse None, never 0)"]
    COUNTS --> ROLLUP["cpe.rollup() —\nworst disposition across all findings"]
    ROLLUP --> SWEEP["4. _sweep_window()\nSEPARATE pass: recent-published CVEs\nper (vendor,product,version) target,\ncross-checked against cpe.py's own\ncomparator (LAW 9 — never trust\nthe source being measured)"]

    SWEEP --> NEVERRAISE2["ALWAYS returns the result dict —\nnever UpdateFailed"]
    NOASSETS --> NEVERRAISE2
    REAUTH --> NEVERRAISE2
    NEVERRAISE2 --> ENTITIES2["5 sensors read coordinator.data:\nactionable, integrity, coverage,\nrollup, recent_affected"]

    style REAUTH fill:#3a2a1a,stroke:#c98a2b,color:#eee
    style NOASSETS fill:#3a1a1a,stroke:#c0392b,color:#eee
```

**`actionable` (KEV-driven) and `window_by_target` (recent-published sweep)
are computed by two separate passes in the same refresh and must never be
merged** — a KEV entry means CISA confirmed active exploitation; a
recent-window CVE only means NVD published it. `cve/coordinator.py` states
this as a named, deliberate separation, not an oversight.

## scan/ — two independent tick shapes

### Agent mode (poll every 10 minutes)

```mermaid
flowchart TD
    TRIGGER2["10min scheduled interval"] --> FETCH2["AgentCoordinator._async_update_data()\nclient.async_get_inventory()"]
    FETCH2 --> RESULT{"result?"}
    RESULT -->|InvalidAuth / NoInventoryYet /\nUnsupportedSchema / CannotConnect| UPDATEFAILED["raise UpdateFailed\n— every scan/ entity goes unavailable\n(never a false empty inventory)"]
    RESULT -->|ok| STATUS2["async_get_status()\n(swallows its own errors -> {} ,\nnever fails the refresh)"]
    STATUS2 --> JOIN["join_hosts(hosts, known_macs,\nacknowledged_macs)\njoin.py — PURE"]
    JOIN --> VIEW["InventoryView assembled"]
    VIEW --> ENTITIES3["Rollup + per-endpoint entities\nread coordinator.data"]

    style UPDATEFAILED fill:#3a1a1a,stroke:#c0392b,color:#eee
```

### Local mode (tick every 5 minutes; a tick is NOT a scan)

```mermaid
flowchart TD
    TICK["LOCAL_TICK = 5min\nLocalCoordinator._async_update_data()"] --> LOAD["store.async_load()\n(idempotent after first call)"]
    LOAD --> SEED["_seed_clocks_from_store()\n(once — recovers due-clocks from\nlast_scan/last_port_scan so a restart\ndoes not fire an immediate full sweep)"]
    SEED --> DUE1{"service scan due?\n(LOCAL_SERVICE_INTERVAL=24h)"}
    DUE1 -->|yes| LAUNCHSVC["_launch('service scan', ...)\nbackground task, tick does NOT await it"]
    DUE1 -->|no| DUE2{"discovery due?\n(LOCAL_DISCOVERY_INTERVAL=1h)"}
    DUE2 -->|yes| LAUNCHDISC["_launch('discovery', ...)"]
    DUE2 -->|no| SKIP["neither launched this tick"]

    LAUNCHSVC --> DUE3
    LAUNCHDISC --> DUE3
    SKIP --> DUE3{"SSH probe due?\n(SSH_PROBE_INTERVAL=6h,\nonly if prober configured)"}
    DUE3 -->|yes| LAUNCHSSH["_launch('ssh probe', ...)"]
    DUE3 -->|no| BUILDVIEW

    LAUNCHSSH --> BUILDVIEW["_build_view()\nre-runs join_hosts() regardless —\nthe registry may have changed\nunderneath even with no new scan"]
    BUILDVIEW --> RETURN["tick returns immediately\n(never awaits a scan)"]

    LAUNCHSVC -.->|"background, on completion"| SCANRUN["scanner.async_scan()\nsubprocess: nmap, ONE AT A TIME\n(asyncio.Lock)"]
    LAUNCHDISC -.->|"background, on completion"| SCANRUN
    SCANRUN -.-> SCANRESULT{"exit ok?"}
    SCANRESULT -.->|"ScanBusy"| IGNORE["not an error — a scan is\nalready running, retry next tick"]
    SCANRESULT -.->|"success or timeout w/ partial XML"| APPLYSCAN["store.apply_scan()\nmerge_inventory() + prune() if complete"]
    APPLYSCAN -.-> PUBLISH["async_set_updated_data(_build_view())\n— published even on failure,\nso a scan never appears to run forever"]

    style RETURN fill:#1a3a2a,stroke:#2b9c6b,color:#eee
    style IGNORE fill:#1a2a3a,stroke:#2b7ac9,color:#eee
```

## On-demand control paths (both modes, via entities or services)

```mermaid
flowchart TD
    BTN["ScanButton.async_press()\nbutton_entities.py"] -->|"coordinator.async_request_scan(profile)"| REQSCAN
    SWT["ScheduleSwitch.async_turn_on/off()\nswitch_entities.py"] -->|"coordinator.async_set_schedule(profile, enabled)"| REQSCHED

    SVC1["service: cyber_estate.custom_scan\nscan_service.py"] -->|"local mode only —\n_one_coordinator() refuses\nif 0 or 2+ local entries"| RUNCUSTOM["coordinator.async_run_custom_scan()"]
    SVC2["service: cyber_estate.scan_device\nscan_service.py"] -->|"resolves device_id -> live IP\nvia coordinator.data.endpoints"| RUNCUSTOM

    REQSCAN -->|agent mode| APIREQ["client.async_request_scan()\nPOST /api/v1/scan — returns\nonce QUEUED, not finished"]
    REQSCAN -->|local mode| RUNCUSTOM
    REQSCHED -->|agent mode| APISCHED["client.async_set_schedule()\nPOST /api/v1/schedule"]
    REQSCHED -->|local mode| SETFLAG["self._enabled[profile] = enabled\n(suppressed, never rescheduled\nfar-future)"]

    RUNCUSTOM --> APPLYSCAN2["store.apply_scan(..., stale_days=None)\n— an on-demand scan NEVER PRUNES"]
    APPLYSCAN2 --> PUBLISH2["async_set_updated_data() immediately"]

    BTN -.->|"3s later (FOLLOWUP_DELAY)"| FOLLOWUP["schedule_followup_refresh()\nasync_call_later -> coordinator.async_request_refresh()\n— NOT optimistic; waits for the\nagent's marker-file side effect to land"]
    SWT -.->|"3s later"| FOLLOWUP
```

## Notes on ordering

- **feeds and cve are guaranteed never to raise, at setup or on refresh** —
  `scan` is the only subsystem whose coordinator can raise, and only
  `ConfigEntryNotReady` at setup (local mode, missing nmap) or
  `UpdateFailed` on refresh (agent mode, connectivity/auth/schema
  failures). `LocalCoordinator`'s own tick never raises — every sweep
  exception is caught inside its background task wrapper and logged.
- **A local-mode tick is deliberately decoupled from a scan actually
  running.** The coordinator's scheduled interval (`LOCAL_TICK`, 5 minutes)
  only decides whether a sweep is *due*; the sweep itself runs as a
  fire-and-forget background task so the tick — and, on first setup,
  `async_config_entry_first_refresh` itself — never blocks on a scan that
  can legitimately run for the better part of an hour.
- **`scan/coordinator.py`'s own comment ("ORDERED CHEAPEST FIRST") is
  imprecise**: the code actually checks whether the expensive 24-hour
  service scan is due *before* checking the cheap 1-hour discovery sweep,
  so an overdue service scan is never starved by an always-current
  discovery sweep. The effect (only one sweep launches per tick, priority
  to the one that has waited longer relative to its own interval) is
  correct; "cheapest first" is not the right label for what the ordering
  achieves.
- **The KEV-driven `actionable` count and the recent-window `by_target`
  sweep inside `cve/` are two passes in the same refresh cycle, run in a
  fixed order** (KEV/actionable first, window sweep second) but are never
  combined into one number — see the `cve/` diagram above.
- **A button press or switch flip never optimistically updates its own
  entity state.** Both wait a fixed 3 seconds (`FOLLOWUP_DELAY`,
  `scan/helpers.py`) before re-reading real state, because the underlying
  action (agent-side) or the schedule flag (local-side) takes effect
  asynchronously relative to the HA service call that requested it.
