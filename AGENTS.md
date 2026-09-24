# AGENTS.md — the rules every agent works under here

This file is for any coding agent (Claude Code, Codex, Gemini CLI, whatever
comes next) working in this repository. It is the same rules whichever tool
reads it; `CLAUDE.md` and `GEMINI.md` are symlinks to it. The estate-wide
rules are `jrackerby/estate`'s `AGENTS.md`; the laws are `jrackerby/HA`'s
`tools/work_docs/LAW.md`; this repo's own traps are `TOOLS.md`.

## Nothing about the household leaves this session

**This repository is PUBLIC, and it is a network scanner.** That combination
makes it the worst place in the estate to be careless: its natural subject
matter — subnets, hosts, MAC addresses, what answers and what does not — is
exactly an attacker's reconnaissance. A test fixture here is a map.

It has already happened. Published while public, and removed 2026-09-23: the
real VLAN plan before and after a migration, three live host addresses, a real
device MAC, and an issue annotating a subnet with what runs on it. Keep all of
the following out of source, comments, commit messages, issue and pull request
text, review comments, test fixtures and CI logs:

- **Addresses and topology.** Real subnets, host addresses, VLAN numbers and
  their purposes, gateway or controller addresses. Use RFC 5737
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and, when a larger
  block is needed, RFC 2544's `198.18.0.0/16`. Those are what this repo's
  fixtures use now.
- **Machines.** Hostnames, hypervisor or container names, device serials,
  unique ids, SSIDs. **MAC addresses** use RFC 7042
  (`00:00:5e:00:53:xx`) — a real OUI names a vendor, and a full MAC names a
  device.
- **People and the home.** Family names, room names, which rooms have a
  screen, when the house is empty. A remark like "on this estate" marks the
  work as one specific house and invites a reader to assemble the rest.
- **Credentials, always.** Tokens, keys, `Authorization` headers.

The test: **would this sentence still make sense if a stranger read it?** If
it only makes sense because you know this network, rewrite it. A fixture does
not need a real address to be a fixture — `198.18.0.0/16` proves a /16 holds
65536 addresses exactly as well as a real one, and `tests/` demonstrates the
whole GH-29 scenario without naming anything that exists.

When a finding genuinely cannot be written without real topology, describe the
shape and say where the detail lives — a private repo or issue — rather than
restating it here.

## How work lands

- **One issue, one branch, one pull request**, and the pull request closes the
  issue it names.
- `tools/run_tests.sh` is the suite. Run it before every push and compare
  against the base: this repo carries a deliberately failing self-test inside
  a suite to prove the harness reports, so a count is only meaningful next to
  the same count on `master`.
- **`manifest.json`'s `version` cuts a release** on a push to the default
  branch.

## How an agent reasons

- **Measure, never infer.** A cause is read off a log, a file, a wire or a
  screen. If you cannot measure it, write "unmeasured" and stop.
- **A green suite is a precondition, not a result.**
- **Every claim carries a timestamp** (LAW §1).
- **Scope is the deliverable.** Do the issue; a second issue is cheap.
