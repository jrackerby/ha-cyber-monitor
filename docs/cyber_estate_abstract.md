# cyber_estate — abstract

Siblings: [`cyber_estate.md`](cyber_estate.md) (technical reference) ·
[`cyber_estate_process_flow.md`](cyber_estate_process_flow.md) (control flow
/ execution order) · [`cyber_estate_data_flow.md`](cyber_estate_data_flow.md)
(data lineage) · [`cyber_estate_architecture.md`](cyber_estate_architecture.md)
(static structure) ·
[`cyber_estate_patent_disclosure.md`](cyber_estate_patent_disclosure.md)
(novelty assessment).

## What this is

This watches the household's digital footprint the way a smoke detector
watches for fire: quietly, continuously, and in a way that is designed to
never mistake "I stopped checking" for "everything is fine."

It does three separate jobs under one roof:

- **It reads public security bulletins** — outbreak notices from the CDC and
  cybersecurity advisories from CISA, the federal cybersecurity agency — and
  keeps a short, current list of the newest ones.
- **It matches known security flaws to what the house actually runs.**
  Software and firmware get patched, but not always right away, and not
  always on every device. This cross-references a public list of actively
  exploited vulnerabilities against the exact version of software each
  device in the house is running, so a flaw only gets flagged if it
  genuinely applies to something here — not just because the vendor's name
  matches.
- **It finds every device on the home network** and keeps an inventory:
  what's connected, what services each device offers, whether a device
  nobody recognizes has shown up, and whether devices that should be
  reachable by remote login actually are.

## Why it exists

A security tool that goes quiet is indistinguishable from a security tool
saying "all clear" — until someone checks and finds out the tool actually
broke weeks ago and nobody noticed. This system's central discipline is
refusing to let that happen: whenever it cannot read a source, cannot reach
a feed, or cannot determine a device's software version, it says so plainly
rather than defaulting to a reassuring blank or a zero. A blank or a zero
looks identical to real good news, and treating them the same way is
precisely how a silent failure goes unnoticed for weeks.

It also refuses to raise a false alarm. A flaw is only called "affects this
house" when the exact version installed on a real device is checked against
the flaw's affected range — not merely because a vendor or product name
looks similar. Two devices from the same manufacturer, running different
software versions, can have completely different answers, and this system
keeps that distinction rather than lumping them together as one guess.

Where a household member has knowingly decided to accept a risk rather than
fix it — for example, an older tablet that is not going to be replaced or
upgraded — that decision is recorded and carried forward visibly, so a real
new problem is never confused with a risk that was already reviewed and
accepted on purpose.

## What it deliberately keeps separate

Home-network cybersecurity findings never mix with the household's physical
safety indicators — fire, break-in, severe weather, and the like — on any
shared display. A vulnerable smart-plug and a smoke alarm are both worth
knowing about, but they call for different reactions from different people
at different times, and folding them into one number would make both
harder to act on correctly. Cybersecurity findings get their own dedicated
space instead.
