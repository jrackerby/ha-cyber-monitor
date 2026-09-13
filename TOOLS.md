# TOOLS

What the tooling does, refuses to do, and lies about, **for the instruments this
repository owns**. Every line is a claim with a timestamp: re-verify before
building a plan on one, and edit it when it stops being true. A capability is
not absent until validated absent.

Scope, so this file does not grow into a second copy of somebody else's:

- **Here**: instruments `cyber_estate` itself drives.
- **NOT here**: Home Assistant's own instrument surface — config entries,
  reloads, restarts, the recorder, the websocket API, `.storage`. Those belong
  to whichever repository owns the instrument, not to this one.
- **Never here**: a rule about how the work is done, rather than a fact about
  an instrument; a description of what currently exists, which goes stale
  faster than anything else in a file like this; and anything unresolved, which
  is an issue on this repository.

## nmap inside the HA core container
- **Present, privileged, NSE-STRIPPED**: `-sS`, `-sn`, `-O` work; `-sV` and `--script`
  fail (`nse_main.lua` missing). **`--datadir /config/nmap-data` restores both** from a
  copied NSE tree, and survives container rebuilds. A scan over 60s cannot run through
  `shell_command`; a custom component owning the subprocess can — which is what
  `scan/scanner.py` is, and why this trap sits in this repository rather than
  beside Home Assistant's own instruments.

## The suite's own dependencies, on a Debian Python
- **`pip install -r tests/requirements.txt` FAILS here, and not over anything this
  repository wrote.** The break is one level down, in the `sgmllib3k` that
  `feedparser==6.0.11` requires: setuptools' `install_lib.finalize_options`
  reads `install_layout` off the `install` command, setuptools' own vendored
  `_distutils` copy carries no such option, so the build dies on
  `AttributeError: install_layout`, no wheel is produced, and every suite that
  loads `feeds/` then fails on `ModuleNotFoundError: No module named 'sgmllib'`.
  **`SETUPTOOLS_USE_DISTUTILS=stdlib` builds it** — Debian patches
  `install_layout` into the stdlib distutils, so the attribute resolves.
  Measured on both arms with `--no-cache-dir`, setuptools 68.1.2 / Python 3.11.
- **pip's wheel cache erases the difference on the second attempt**, which is how
  this reads as already fixed: once the wheel exists, an install WITHOUT the
  variable succeeds from cache. An A/B that omits `--no-cache-dir` reports the
  workaround as unnecessary and is measuring the cache, not the build.
- **A red seventh suite here over a green `tests` job is this trap, not a
  regression** — that job runs the workflow's own Python and is green on master.
  Reaching for that conclusion without the install above is how a pass ships
  having exercised six of its seven suites and says so only in a commit message.
