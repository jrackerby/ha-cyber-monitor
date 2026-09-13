# cyber_estate — invention disclosure draft

Siblings: [`cyber_estate.md`](cyber_estate.md) (technical reference) ·
[`cyber_estate_process_flow.md`](cyber_estate_process_flow.md) (control flow
/ execution order) · [`cyber_estate_data_flow.md`](cyber_estate_data_flow.md)
(data lineage) · [`cyber_estate_architecture.md`](cyber_estate_architecture.md)
(static structure) · [`cyber_estate_abstract.md`](cyber_estate_abstract.md)
(plain-language summary).

> **This is an internal invention-disclosure draft, not a filed patent
> application and not legal advice.** It is written in patent-specification
> form (numbered paragraphs, formal claim language) as a documentation
> exercise and as a starting point should this ever go to actual patent
> counsel. No prior-art search, novelty opinion, or freedom-to-operate
> analysis has been performed. Every specific figure is drawn from
> `custom_components/cyber_estate/` as read this session and is presented
> as "one embodiment" where a claim is asserted — the actual patent-claim
> scope, if pursued, would be drafted and narrowed by counsel, not by this
> file.

## TITLE OF THE INVENTION

OWNERSHIP-VALIDATED ASSET IDENTITY RESOLUTION FOR VULNERABILITY DISPOSITION
IN A HETEROGENEOUS DEVICE REGISTRY

## FIELD OF THE INVENTION

[0001] The present disclosure relates to automated network security
monitoring systems, and more particularly to a system and method for
determining, from a heterogeneous device registry maintained by a
home- or premises-automation platform, which software/firmware version
record for a given physical asset is authoritative for the purpose of
vulnerability disposition, where the registry may hold more than one record
purporting to describe the same physical device.

## BACKGROUND OF THE INVENTION

[0002] Automated vulnerability-management systems commonly disposition a
known vulnerability against an installed asset by comparing a recorded
software or firmware version against a published affected-version range.
The correctness of this comparison depends entirely on the recorded version
being the version the asset actually runs.

[0003] **The deficiency this disclosure addresses.** In a device registry
populated by multiple independent, uncoordinated data-collecting
subsystems (each associated with its own configuration entry or
equivalent ownership record), a single physical device may come to be
represented by more than one registry record. This occurs, without
malicious intent or configuration error, when a device's identity is
initially discovered and recorded by one subsystem (for example, a network
inventory service that observes the device answering a discovery protocol)
and is later also recorded, under a shared or overlapping identifying
attribute (for example, a hardware address visible on the network), by a
second, unrelated subsystem that has no purpose-built means of tracking
that device's current software version. The second subsystem's record
persists in the registry, frozen at whatever version string it inherited
or was seeded with, indefinitely — because the subsystem that created it
has no reason, and often no mechanism, to update a field it does not
understand the meaning of.

[0004] A vulnerability-disposition system that queries the registry naively
— by physical or logical identity alone, without regard to which
subsystem's record it is reading — cannot distinguish the frozen,
non-authoritative record from the live, authoritative one. Measured in one
implementation: three physical hosts of the same hardware class each held
two registry records — one maintained by the subsystem that actually runs
on the host and updates its software-version field on every observation,
and a second, orphaned record belonging to a device-tracking subsystem
that had briefly captured the same hardware address and then never
touched the field again. The orphaned records reported a materially older
software version than the hosts actually ran. A vulnerability disposition
computed against the orphaned records' version reported multiple critical
findings against software that was not, in fact, installed anywhere on the
monitored estate — a false-positive class distinct from, and not addressed
by, ordinary version-comparison logic.

[0005] The naive corrective — discriminating registry records by some
structural property of the record itself (for example, the presence or
absence of a particular optional field) — is unsound, because the
structural property in question is not reliably correlated with which
record is authoritative. In the same implementation, the single
highest-value asset in the monitored estate (a network gateway device)
happened to share the same structural property as the orphaned,
non-authoritative records of the unrelated device class; a filter built on
that property would have silently excluded the gateway from vulnerability
monitoring entirely, which is a strictly worse outcome than the
false-positive it would have fixed.

[0006] There is accordingly a need for a method of selecting the
authoritative version record for a physical asset represented by multiple
registry entries that discriminates on a signal the registry itself
maintains as a matter of its own bookkeeping — rather than on the
structure or shape of the asset record's own optional fields — and that
fails, when the signal is itself absent or indeterminate, in the direction
of retaining rather than excluding the asset from monitoring.

## SUMMARY OF THE INVENTION

[0007] In one aspect, a set of matching rules associates a physical-asset
identification pattern (matched against manufacturer and model strings
recorded in a device registry) with one or more product identifiers used
by an external vulnerability database, and additionally associates each
matching rule with a designated owning subsystem identifier. When a
registry record matching a rule's identification pattern is evaluated, the
method determines the identifier of the subsystem that currently owns
(is the origin of / has current write authority over) that specific
registry record — not the asset generally, but the specific record being
evaluated — and compares it against the rule's designated owning subsystem
identifier. A record whose owning-subsystem identifier does not match the
rule's designated identifier is excluded from contributing a version value
for vulnerability-disposition purposes, and the exclusion, together with
the specific reason (the mismatched owner identifiers), is recorded as a
retrievable fact rather than silently omitted.

[0008] In a second aspect, a registry record for which the owning-subsystem
identifier cannot be determined (as opposed to being determined and
mismatched) is treated as unconstrained by the ownership check and is
retained for vulnerability-disposition purposes — the two failure
directions (a determinable, mismatched owner, versus an indeterminate
owner) are deliberately given opposite dispositions, because the harm of
wrongly excluding a genuine asset from a security scan is judged greater
than the harm of wrongly retaining a possibly-stale one, and only the
former is structurally guarded against by the first aspect.

[0009] In a third aspect, the vulnerability-disposition value computed
from a version so validated is combined with an independent per-asset
disposition — an "accepted" or risk-acknowledged state, assigned by a
separate, static rule set keyed to the same asset-identification pattern
— such that an asset already subject to a standing risk-acceptance
determination reports a disposition distinguishing "known and accepted"
from "not tracked by any rule," while a vulnerability match against that
asset's declared product identifiers is still recorded and retrievable,
rather than the accepted asset being omitted from matching altogether.

## BRIEF DESCRIPTION OF THE DRAWINGS

[0010] FIG. 1 is a block-flow diagram illustrating asset discovery: a
device-registry read stage, a rule-matching stage, an ownership-resolution
stage, and the resulting three-way asset classification (mapped / accepted
/ unmapped-with-reason).

[0011] FIG. 2 is a decision diagram illustrating the ownership-validation
logic of the first and second aspects: a matched rule proceeds to
disposition only if the record's owning-subsystem identifier is either
unconstrained (unknown) or equal to the rule's designated owner; a
determinable mismatch routes to an explicitly-reasoned exclusion rather
than a silent drop.

## DETAILED DESCRIPTION OF THE PREFERRED EMBODIMENT

[0012] Referring to FIG. 1, a device registry maintained by a home- or
premises-automation platform is walked at each of a series of refresh
intervals, in one embodiment every six hours. Each registry record
carries, in addition to manufacturer/model/version fields, an indication
of the configuration entry or subsystem currently associated with that
specific record (in one embodiment, a "primary config entry" reference
maintained by the platform itself as part of its own device-registry
bookkeeping, independent of and not writable by the vulnerability-
disposition system).

[0013] **Ownership-validated matching (first and second aspects).** A set
of matching rules, each associating a manufacturer/model substring pattern
with one or more external-database product identifiers and, for at least
one rule, a designated owning-subsystem identifier, is evaluated against
each registry record in a fixed order (risk-acceptance rules before
general asset rules). For a record matching a rule that declares an
owning-subsystem identifier, the record's own current owning-subsystem
identifier — read from the platform's device-registry bookkeeping, not
inferred from the record's shape or contents — is compared against the
rule's declared identifier. Three outcomes result: (a) the identifiers
match, or the rule declares no owning-subsystem constraint, or the
record's owning-subsystem identifier cannot be determined — in each of
these cases the record is retained and its version value is used for
disposition; (b) the identifiers are both determinable and unequal — the
record is excluded from disposition, and the exclusion is recorded
together with the mismatched identifiers as an attribute retrievable by a
downstream consumer, distinguishing this case from an asset that no rule
addressed at all.

[0014] The deliberate asymmetry between an *indeterminate* owner
(retained) and a *determined-and-mismatched* owner (excluded) is the
inventive step distinguishing this method from a simpler validation that
either always excludes on any owner-related uncertainty or never checks
ownership at all. The former direction (excluding on indeterminacy)
converts every asset whose ownership cannot presently be determined into a
monitoring blind spot; the latter (never checking) reintroduces the
false-positive defect of the Background. The method as claimed excludes
only the case that is both checkable and affirmatively wrong.

[0015] **Discrimination signal.** The signal used for ownership validation
is a piece of bookkeeping the platform's own registry infrastructure
maintains as an ordinary incident of managing multiple concurrently
active subsystems — it is not a property of the asset record's own
declared fields (manufacturer, model, version, or the presence/absence of
any optional attribute), and no subsystem other than the platform itself
can assert or forge it on behalf of another. This is what makes the
signal reliable in the specific failure case of the Background: a
non-authoritative record and an authoritative one for the same physical
device can be structurally identical or even structurally indistinguishable
from a legitimately-differently-shaped record belonging to an unrelated
asset, but they cannot share a falsely-claimed owning-subsystem identifier
without the platform's own registry infrastructure being compromised.

[0016] **Combination with static risk-acceptance (third aspect).** A
second, disjoint rule set associates certain asset-identification patterns
with a fixed "accepted" disposition and a human-readable reason, evaluated
before the general matching rules of paragraph [0013] (a match under this
rule set short-circuits further classification). Critically, an asset
classified as accepted may still declare product identifiers for
vulnerability-database matching purposes; a vulnerability match against
those identifiers is disclosed with a disposition value distinguishing
"matched, and previously accepted by a standing determination" from both
"matched, unresolved" and "no rule addresses this asset's product at
all" — three distinct facts that a system omitting the accepted asset
from matching entirely, or merging accepted assets into a general
"not tracked" bucket, cannot represent.

## CLAIMS

**1.** A computer-implemented method for validating an asset-version
record prior to its use in a vulnerability-disposition computation, the
method comprising:

&nbsp;&nbsp;(a) reading, from a device registry maintained by an
automation platform, a plurality of asset records, each asset record
comprising a manufacturer identifier, a model identifier, a version value,
and a current owning-subsystem identifier maintained by the platform
independently of the asset record's own manufacturer, model, and version
fields;

&nbsp;&nbsp;(b) matching a given asset record against a rule from a set of
matching rules, the rule associating a manufacturer/model pattern with one
or more vulnerability-database product identifiers and, for at least one
rule in the set, a designated owning-subsystem identifier;

&nbsp;&nbsp;(c) responsive to the matched rule declaring a designated
owning-subsystem identifier, comparing the asset record's current
owning-subsystem identifier against the rule's designated owning-subsystem
identifier; and

&nbsp;&nbsp;(d) responsive to determining that the asset record's current
owning-subsystem identifier is determinable and does not equal the rule's
designated owning-subsystem identifier, excluding the asset record's
version value from the vulnerability-disposition computation and
recording an indication of the exclusion together with both compared
identifiers, retrievable independently of the vulnerability-disposition
computation's own output.

**2.** The method of claim 1, further comprising: responsive to
determining that the asset record's current owning-subsystem identifier
cannot be determined, including the asset record's version value in the
vulnerability-disposition computation notwithstanding the rule's declared
owning-subsystem identifier — such that an indeterminate ownership signal
and a determined-and-mismatched ownership signal produce opposite
inclusion outcomes.

**3.** The method of claim 1, wherein the current owning-subsystem
identifier is read from a registry-maintained association between the
asset record and a configuration entry, established and updated by the
automation platform's own device-registry infrastructure independently of
any process that could also write the asset record's manufacturer, model,
or version fields.

**4.** The method of claim 1, further comprising: evaluating, prior to
step (b), the asset record against a second, disjoint set of rules each
associating a manufacturer/model pattern with a fixed risk-accepted
disposition and a stored reason; responsive to a match under the second
rule set, assigning the asset record the risk-accepted disposition while
still permitting the asset record to declare one or more vulnerability-
database product identifiers for matching; and responsive to a
subsequent vulnerability-database match against those product
identifiers, producing a disposition value distinguishing the
risk-accepted case from both an unresolved match and the absence of any
applicable rule.

**5.** A computer-implemented system comprising a processor and memory
storing instructions that, when executed, cause the system to perform the
method of claim 1, wherein the vulnerability-disposition computation
additionally applies a version-range comparison in which any comparison
step that cannot be completed with a successfully-parsed version value
and a successfully-parsed range bound returns a value distinct from, and
never collapsing into, a value indicating the asset is unaffected.

## ABSTRACT

A method for validating which of possibly several device-registry records
describing the same physical asset is authoritative for vulnerability
disposition, in a registry populated by multiple independent, uncoordinated
subsystems. A matching rule associates an asset-identification pattern
with both a set of vulnerability-database product identifiers and a
designated owning-subsystem identifier; a candidate record's actual
current owning-subsystem identifier — a signal maintained by the platform's
own registry infrastructure and not forgeable by the record's own
declared fields — is compared against the rule's designated identifier.
A determined mismatch excludes the record's version from disposition,
with the exclusion and its reason recorded as a retrievable fact; an
indeterminate owner does not exclude the record, deliberately biasing
uncertain cases toward continued monitoring rather than toward a
blind spot. The method is combined with a disjoint, static
risk-acceptance rule set so that an asset already subject to a standing
risk determination still participates in vulnerability matching, with its
own distinct disposition value, rather than being omitted from scanning.

## Assessment of the rest of `cyber_estate`

The claims above are scoped narrowly to the ownership-validation
mechanism in `cve/coordinator.py`'s `_owner_domain()` /
`cve/cpe.py`'s `_owner_ok()`/`classify_device()`, because it is the one
piece of this integration's design that is not a straightforward
application of a documented pattern. Everything else examined this
session is genuine, careful engineering but does not clear the bar for a
claim:

- **`feeds/`** is a bounded-fetch-then-pure-parse wrapper around a
  standard library (`feedparser`) and a `DataUpdateCoordinator`. The
  disposition-preserving discipline (never let an unreadable source read
  as zero) is the same pattern already disclosed, with real claims, in
  `household_alert_patent_disclosure.md` for `household_state` — this
  integration applies that pattern, it does not extend it.
- **`cve/cpe.py`'s asymmetric "never guess PATCHED" version comparator**
  is careful and its edge cases (the `vulnerable: false` platform-node
  exclusion that prevented Linux kernels from being reported affected by
  a Chromium bug; the exact-version CPE string being converted to a
  pseudo-bound rather than read as "no bounds") are real, measured, and
  worth the documentation they already have in the code's own self-test —
  but a strict-refuse-on-ambiguity version comparator is a known,
  well-established pattern in vulnerability-management tooling generally
  (most CVE scanners refuse to assert "not affected" on an unparseable
  version), not a novel one.
- **`scan/`'s two-mode (local nmap subprocess vs. remote HTTP agent)
  architecture, its three-bucket MAC join (`matched`/`unmatched`/
  `acknowledged`), its dynamic per-service entity creation, and its
  three-state (`open`/`closed`/`never_scanned`) service-reading vocabulary**
  are all well-executed instances of established patterns — a subprocess
  wrapper around a standard scanning tool, a set-difference/join over
  normalized identifiers, dynamic entity discovery, and a tri-state
  "unknown vs. negative" distinction that is, again, the same general
  discipline already claimed for `household_state`. None of these
  individually or in combination is a departure from documented network-
  scanning or home-automation integration practice.
- **The card-local 0-7 cyber-severity rollup** (`cyber-alerts-card.js`'s
  `_cyberRollup()`) lives outside `custom_components/cyber_estate/`
  entirely and is a simple worst-of-N-rows computation; it is not part of
  this disclosure's subject matter.

No claim is asserted for any of the above; the ownership-validation
mechanism above is the sole aspect of this integration judged to warrant
drafted claim language.

---

*Reference implementation: `custom_components/cyber_estate/cve/coordinator.py`
(`_owner_domain`, `_discover`), `custom_components/cyber_estate/cve/cpe.py`
(`_owner_ok`, `classify_device`), `custom_components/cyber_estate/cve/const.py`
(`ASSET_RULES`' `owner` field), version 1.0.0, as read in full this session.
See `docs/integrations/cyber_estate.md` for the current operational
reference and `jrackerby/HA` `docs/PROCESS.md` for the documentation method used across
this repo's `docs/integrations/` tree.*
