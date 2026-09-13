# Defensive automations

Templates for acting on what Cyber Monitor flags. Every one is copy-and-edit:
the entity ids and notify targets are placeholders, and the ones that change
something on the network are gated behind an arming toggle you create.

## What you can trigger on

Two binary sensors, one event stream. All three are **debounced and
rate-limited by the integration** — see *Options → When a finding becomes an
alert* — so an automation here can be simple. It does not need its own
flicker guard; it needs to decide what to do.

| Surface | Fires when |
|---|---|
| `binary_sensor.<scanner>_unknown_host_present` | at least one unaccounted-for host has been confirmed on the network |
| `binary_sensor.nvd_vulnerabilities_actionable_vulnerability` | the CVE join reports at least one AFFECTED finding |
| event `cyber_estate_event` | any of the above changes — one event per host, per edge |

The event carries `type` and a payload:

| `type` | payload |
|---|---|
| `unknown_host_detected` | `mac`, `ip`, `hostname`, `vendor`, `os`, `open_ports` |
| `unknown_host_cleared` | same fields, last known |
| `vulnerability_actionable` | `count`, `overdue`, `ransomware_linked`, `affected[]` (`cve`, `product`, `device`, `version`, `fixed_in`) |
| `vulnerability_cleared` | same shape, count 0 |

Plus `entry_id` on every event.

**Event or state?** Trigger on the **event** when the action is per host — the
event names the host, the flag only says *one or more*. Trigger on the **flag**
when the action is about the network's posture as a whole (arm the alarm,
turn a wall red, page someone).

### How the debounce and the limits behave

- A finding is confirmed after it has been present in *N* consecutive scans
  (default 2) and cleared after *M* consecutive absences (default 2). One
  hourly discovery sweep is one observation, so the default is two hours to
  raise on a new host. Set *Scans to confirm* to 1 if you want the latency
  instead of the false-positive protection.
- Once a flag changes it holds for the *minimum hold* (default 5 minutes)
  before it may change again. A change arriving inside the hold is applied at
  the end of it; `deferred_changes` on the entity counts how many there were.
- At most *events per hour, per type* (default 12) reach the bus. Anything
  over is dropped and counted in the flag's `events_suppressed` attribute —
  **a defensive automation should watch that attribute too**, because a burst
  large enough to trip it is itself a finding.
- An acknowledged MAC is *forgotten*, never *cleared*: acknowledging a host
  does not fire `unknown_host_cleared`, because the host did not leave.

Read the flag's attributes to see the state behind it: `hosts` (confirmed),
`pending` (seen, awaiting confirmation, with `observations`/`needed`),
`clearing`, `held_until`, `last_observed`, `events_sent_last_hour`,
`events_suppressed`, and the `policy` in force.

---

## 1. Tell someone, with the host's details

The baseline. Runs once per detected host, and the integration's own rate
limit bounds it.

```yaml
alias: Cyber - unknown host detected
description: Notify with the host's identity the moment the scanner confirms it.
mode: queued
max: 10
triggers:
  - trigger: event
    event_type: cyber_estate_event
    event_data:
      type: unknown_host_detected
actions:
  - action: notify.mobile_app_YOUR_PHONE
    data:
      title: "Unknown host on the network"
      message: >-
        {{ trigger.event.data.hostname or trigger.event.data.ip }}
        ({{ trigger.event.data.mac }}, {{ trigger.event.data.vendor or 'vendor unknown' }})
        {% if trigger.event.data.open_ports %}
        open: {{ trigger.event.data.open_ports | join(', ') }}
        {% endif %}
      data:
        tag: "unknown-host-{{ trigger.event.data.mac | replace(':', '') }}"
        notification_icon: mdi:lan-disconnect
  - action: persistent_notification.create
    data:
      notification_id: "unknown_host_{{ trigger.event.data.mac | replace(':', '') }}"
      title: "Unknown host: {{ trigger.event.data.hostname or trigger.event.data.ip }}"
      message: >-
        MAC {{ trigger.event.data.mac }} · IP {{ trigger.event.data.ip }} ·
        {{ trigger.event.data.vendor or 'vendor unknown' }}.
        Acknowledge it under Cyber Monitor → Configure if it is yours.
```

Clear the notification when the host leaves:

```yaml
alias: Cyber - unknown host cleared
mode: queued
triggers:
  - trigger: event
    event_type: cyber_estate_event
    event_data:
      type: unknown_host_cleared
actions:
  - action: persistent_notification.dismiss
    data:
      notification_id: "unknown_host_{{ trigger.event.data.mac | replace(':', '') }}"
  - action: notify.mobile_app_YOUR_PHONE
    data:
      message: "clear_notification"
      data:
        tag: "unknown-host-{{ trigger.event.data.mac | replace(':', '') }}"
```

## 2. Look harder before deciding — rescan the host

The discovery sweep only knows the host is up. A service scan on that one
address says what it is running, which is usually what tells a smart plug from
a laptop. `cyber_estate.scan_device` takes the endpoint's **device**, which the
integration created the moment the host was seen.

There is no template function that looks a device up by MAC — `device_id()`
takes an entity id or a device *name*. Every endpoint device carries its MAC
as a network connection, so find it through the integration's own entities:

```yaml
alias: Cyber - rescan a newly confirmed host
mode: queued
triggers:
  - trigger: event
    event_type: cyber_estate_event
    event_data:
      type: unknown_host_detected
variables:
  mac: "{{ trigger.event.data.mac | lower }}"
  device: >-
    {% set ns = namespace(id=none) %}
    {% for e in integration_entities('cyber_estate') if ns.id is none %}
      {% set d = device_id(e) %}
      {% if d and ('mac', mac) in (device_attr(d, 'connections') or []) %}
        {% set ns.id = d %}
      {% endif %}
    {% endfor %}
    {{ ns.id if ns.id is not none else '' }}
actions:
  - condition: template
    value_template: "{{ device != '' }}"
  - action: cyber_estate.scan_device
    data:
      device_id: "{{ device }}"
      service_versions: true
      os_detect: true
  - action: notify.mobile_app_YOUR_PHONE
    data:
      title: "Rescanned {{ trigger.event.data.ip }}"
      message: >-
        {{ device_name(device) }}: open the device page for services and OS.
```

If `device` renders empty the host has no device record yet — the next
coordinator tick adds it; the automation simply skips this time.

## 3. Take the host off the network — gated

This one changes the network. It is armed by a toggle **you** create, so an
untested automation cannot block a guest's phone on its first night:

```yaml
# Helpers → Toggle. Off by default. Turn it on when you trust the pipeline.
input_boolean.auto_block_unknown_hosts
```

Two ways to block, pick the one your controller supports.

**UniFi**, when the integration is set to create block switches for clients
(UniFi → Configure → *Network access controlled clients*): each such client
gets `switch.<client name>_blocked`. **On means network access is allowed**
(`is_on` is `not client.blocked`), so blocking is `switch.turn_off`. The
entity id is the client's UniFi name, not its MAC, and the UniFi client
device is a *separate* device record from Cyber Monitor's endpoint (Home
Assistant does not merge devices across integrations on a shared MAC), so
resolve it by MAC connection on the UniFi side:

```yaml
alias: Cyber - block a confirmed unknown host (UniFi)
description: Off by default; armed by input_boolean.auto_block_unknown_hosts.
mode: queued
triggers:
  - trigger: event
    event_type: cyber_estate_event
    event_data:
      type: unknown_host_detected
conditions:
  - condition: state
    entity_id: input_boolean.auto_block_unknown_hosts
    state: "on"
  # Never act on a flag whose event stream is being throttled -- something
  # bigger than one host is happening, and a person should look.
  - condition: template
    value_template: >-
      {{ (state_attr('binary_sensor.network_inventory_unknown_host_present', 'events_suppressed')
          or {}) | length == 0 }}
variables:
  mac: "{{ trigger.event.data.mac | lower }}"
  block_switch: >-
    {% set ns = namespace(found=none) %}
    {% for e in integration_entities('unifi') | select('match', 'switch\\.') if ns.found is none %}
      {% set d = device_id(e) %}
      {% if d and e.endswith('_blocked') and ('mac', mac) in (device_attr(d, 'connections') or []) %}
        {% set ns.found = e %}
      {% endif %}
    {% endfor %}
    {{ ns.found if ns.found is not none else '' }}
actions:
  - choose:
      - conditions: "{{ block_switch != '' }}"
        sequence:
          - action: switch.turn_off
            target:
              entity_id: "{{ block_switch }}"
          - action: notify.mobile_app_YOUR_PHONE
            data:
              title: "Blocked unknown host"
              message: "{{ trigger.event.data.ip }} ({{ mac }}) blocked at the controller. To unblock, turn {{ block_switch }} back on."
    default:
      - action: notify.mobile_app_YOUR_PHONE
        data:
          title: "Unknown host NOT blocked"
          message: >-
            {{ trigger.event.data.ip }} ({{ mac }}) has no UniFi block switch —
            add the client under the UniFi integration's options, or block it by hand.
```

**Any controller with an HTTP API**, via a `rest_command` you define — the
UniFi Network API is shown; substitute your own:

```yaml
# configuration.yaml
rest_command:
  unifi_block_mac:
    url: "https://YOUR_CONTROLLER/proxy/network/api/s/default/cmd/stamgr"
    method: POST
    headers:
      X-API-KEY: !secret unifi_api_key
      Content-Type: application/json
    payload: '{"cmd": "block-sta", "mac": "{{ mac }}"}'
    verify_ssl: false
```

```yaml
actions:
  - action: rest_command.unifi_block_mac
    data:
      mac: "{{ trigger.event.data.mac | lower }}"
```

**Nothing here unblocks automatically.** `unknown_host_cleared` means the host
stopped answering — which is exactly what a blocked host does. Unblocking is a
decision, and the notification names the switch to flip.

## 4. Escalate a vulnerability by what it carries

`vulnerability_actionable` fires when the affected count rises from zero. The
payload says whether any finding is past its CISA due date or ransomware-linked,
so one automation can route two urgencies.

```yaml
alias: Cyber - actionable vulnerability
mode: single
triggers:
  - trigger: event
    event_type: cyber_estate_event
    event_data:
      type: vulnerability_actionable
variables:
  urgent: "{{ trigger.event.data.overdue > 0 or trigger.event.data.ransomware_linked > 0 }}"
  summary: >-
    {% for f in trigger.event.data.affected[:5] %}
    {{ f.cve }} — {{ f.product }} on {{ f.device }}{% if f.fixed_in %} (fixed in {{ f.fixed_in }}){% endif %}
    {% endfor %}
actions:
  - action: todo.add_item
    target:
      entity_id: todo.patching
    data:
      item: >-
        Patch {{ trigger.event.data.count }} affected finding(s):
        {{ trigger.event.data.affected | map(attribute='cve') | unique | join(', ') }}
  - choose:
      - conditions: "{{ urgent }}"
        sequence:
          - action: notify.mobile_app_YOUR_PHONE
            data:
              title: "URGENT: exploited-in-the-wild vulnerability on the estate"
              message: "{{ summary }}"
              data:
                priority: high
                ttl: 0
                channel: alarm_stream
    default:
      - action: notify.mobile_app_YOUR_PHONE
        data:
          title: "Actionable vulnerability"
          message: "{{ summary }}"
```

## 5. Posture on the flag, not the event

When the action is about the *network* rather than one host, trigger on the
binary sensor. `for:` adds an automation-side dwell on top of the integration's
debounce — use it for actions with a cost, such as arming an alarm profile or
turning a wall red for the household.

```yaml
alias: Cyber - posture while an unknown host is present
mode: restart
triggers:
  - trigger: state
    entity_id: binary_sensor.network_inventory_unknown_host_present
    to: "on"
    for: "00:10:00"
    id: raised
  - trigger: state
    entity_id: binary_sensor.network_inventory_unknown_host_present
    to: "off"
    id: cleared
actions:
  - choose:
      - conditions:
          - condition: trigger
            id: raised
        sequence:
          - action: input_select.select_option
            target:
              entity_id: input_select.cyber_posture
            data:
              option: Elevated
      - conditions:
          - condition: trigger
            id: cleared
        sequence:
          - action: input_select.select_option
            target:
              entity_id: input_select.cyber_posture
            data:
              option: Normal
```

Keep cyber posture on its own surface. It never feeds a physical household
directive.

## 6. Watch the limiter itself

A rate limit that trips is a finding: a burst of detections means a scope
change, a new segment, a rogue DHCP server, or a scanner fault — none of which
one blocked MAC fixes. Page a person and stop the automated blocking until
someone looks.

```yaml
alias: Cyber - event stream throttled
mode: single
triggers:
  - trigger: template
    value_template: >-
      {{ (state_attr('binary_sensor.network_inventory_unknown_host_present', 'events_suppressed')
          | default({})).get('unknown_host_detected', 0) | int > 0 }}
actions:
  - action: input_boolean.turn_off
    target:
      entity_id: input_boolean.auto_block_unknown_hosts
  - action: notify.mobile_app_YOUR_PHONE
    data:
      title: "Cyber Monitor is throttling detections"
      message: >-
        More than the hourly cap of unknown-host events fired.
        {{ state_attr('binary_sensor.network_inventory_unknown_host_present', 'host_count') }} hosts confirmed,
        {{ state_attr('binary_sensor.network_inventory_unknown_host_present', 'pending') | length }} pending.
        Automatic blocking has been disarmed.
      data:
        priority: high
```

The suppressed counters reset when the integration restarts, so this fires at
most once per burst per restart.

## Rate-limiting inside an automation

The integration already bounds events per hour. If an action is expensive
enough to want a tighter bound of its own — a phone call, an SMS — gate it on
the automation's own last run:

```yaml
conditions:
  - condition: template
    value_template: >-
      {{ this.attributes.last_triggered is none
         or (now() - this.attributes.last_triggered) > timedelta(minutes=30) }}
```

`mode: single` with a long-running action is the other way: while the action
runs, further triggers are dropped and logged.
