"""Runs nmap from inside Home Assistant, asynchronously.

WHY THIS IS NOT A `shell_command`. `shell_command` hard-kills its subprocess at
60 seconds, which is fine for a liveness sweep and impossible for a full-port
scan of a subnet. Owning the subprocess here removes that ceiling entirely: the
timeout becomes a property of the scan being asked for rather than of the
transport, and a long scan reports progress instead of being killed mid-run and
looking like a crash.

ONE SCAN AT A TIME, ESTATE-WIDE. Two nmap processes on one interface interfere:
they compete for the same ARP cache and congestion window, and the slower one
reports ports as filtered that the faster one saw open. The lock means a second
request WAITS or is REFUSED -- it never silently produces a worse answer than
the same request made alone.

NOTHING IS WRITTEN TO DISK BY NMAP. XML comes back on stdout (`-oX -`), so a
runaway scan cannot fill the config volume, and there is no scan directory to
retain, rotate or leak.

THE OUTPUT IS PARSED EVEN WHEN NMAP REPORTS FAILURE. A scan interrupted partway
still emits well-formed XML for the hosts it finished, and those observations
are real. What must never happen is a partial scan being merged as though it
were complete -- so a partial result is returned WITH `complete=False`, and the
caller decides. Merging a partial port scan as complete would read as "these
services closed".
"""

from __future__ import annotations

import asyncio
import logging
import shutil
from dataclasses import dataclass
from typing import Any

from .coverage import derive_discovery_timeout
from .options import build_args
from .parse import parse_scan

_LOGGER = logging.getLogger(__name__)

# Generous, because the alternative failure is worse. A deep scan of a /24 can
# legitimately run for well over an hour, and a timeout that fires on a healthy
# scan destroys the one result that took longest to get. This is a runaway
# backstop, not a schedule.
DEFAULT_TIMEOUT = 3600

# THE LIVENESS BACKSTOP IS NOT A CONSTANT HERE ANY MORE. It is an options key
# resolved by `settings.resolve_settings`, falling back to a budget derived
# from the configured scope -- both in `scan/const.py` and
# `coverage.derive_discovery_timeout`, because a number this file invented
# while the scope was configurable elsewhere is the defect GH-34 records.
# The scheduled sweeps pass the resolved value; `derive_discovery_timeout` is
# what any other caller gets.

# nmap writes progress and warnings to stderr in normal operation, so stderr is
# NOT an error signal. Only this much is kept for diagnostics.
MAX_STDERR = 4000


class ScanError(Exception):
    """A scan that could not be run or produced nothing usable."""


class ScanBusy(ScanError):
    """A scan is already running. Deliberately distinct from a failure."""


@dataclass(slots=True)
class ScanResult:
    """What one nmap invocation produced."""

    hosts: dict[str, dict[str, Any]]
    args: list[str]
    duration: float
    returncode: int
    # False when nmap exited non-zero or timed out but still gave us XML. The
    # hosts present are real; the ABSENCE of a host means nothing.
    complete: bool = True
    stderr: str = ""
    timed_out: bool = False

    @property
    def host_count(self) -> int:
        return len(self.hosts)


def find_nmap() -> str | None:
    """Absolute path to nmap, or None. Blocking -- call in an executor."""
    return shutil.which("nmap")


class NmapScanner:
    """Serialised access to the local nmap binary."""

    def __init__(self, hass, binary: str, datadir: str | None = None) -> None:
        self._hass = hass
        self._binary = binary
        # None when the NSE tree is absent. Carried rather than defaulted so a
        # missing tree degrades LOUDLY at the one place that can report it,
        # instead of every -sV scan failing with a Lua error.
        self._datadir = datadir
        self._lock = asyncio.Lock()
        self._current: str | None = None

    @property
    def datadir(self) -> str | None:
        return self._datadir

    @property
    def can_detect_services(self) -> bool:
        """Whether -sV and --script will work at all.

        Home Assistant's bundled nmap has no script engine, so without a
        datadir supplying one, every service-detection scan fails. Surfaced as
        a property so the integration can say so once, up front, rather than
        letting each scan discover it separately.
        """
        return self._datadir is not None

    @property
    def busy(self) -> bool:
        return self._lock.locked()

    @property
    def current_scan(self) -> str | None:
        """A human label for what is running, or None."""
        return self._current

    async def async_scan(
        self,
        targets: list[str],
        option_keys: list[str] | None = None,
        exclude: list[str] | None = None,
        discovery_only: bool = False,
        timeout: int | None = None,
        label: str = "scan",
        wait: bool = False,
    ) -> ScanResult:
        """Run one scan. Raises ScanBusy, ScanError or InvalidScanRequest.

        `wait=False` REFUSES rather than queues. A button press that silently
        waited twenty minutes behind a deep scan would look like it did
        nothing; refusing says what happened while it is still true.
        """
        # Built BEFORE the lock so an invalid request fails fast and does not
        # occupy the scanner while being rejected.
        args = build_args(
            targets,
            option_keys=option_keys,
            exclude=exclude,
            discovery_only=discovery_only,
            datadir=self._datadir,
        )

        # REFUSE RATHER THAN RUN A SCAN THAT CANNOT ANSWER. Without the script
        # engine, -sV exits non-zero having found nothing, which merges as "no
        # services here" -- a confident wrong answer about every host scanned.
        needs_nse = {"service_versions", "default_scripts"} & set(option_keys or [])
        if needs_nse and not self.can_detect_services:
            raise ScanError(
                "service detection needs nmap's script engine, which this "
                "Home Assistant container does not ship. Install an NSE tree "
                f"and point the integration at it (expected {self._datadir!r})."
            )

        if self._lock.locked() and not wait:
            raise ScanBusy(f"a scan is already running ({self._current})")

        async with self._lock:
            self._current = label
            try:
                # `targets`, the caller's list: `build_args` above has already
                # run `validate_target` over every one of them and raises on a
                # bad one, so anything reaching here is a shape
                # `address_count` understands.
                return await self._run(
                    args, timeout, discovery_only, targets=targets
                )
            finally:
                self._current = None

    async def _run(
        self,
        args: list[str],
        timeout: int | None,
        discovery_only: bool,
        targets: list[str] | None = None,
    ) -> ScanResult:
        if timeout is None:
            # A CALLER THAT PASSED ONE ALREADY WON, above: the scheduled
            # sweeps hand over `settings.discovery_timeout`, which is the
            # operator's value when they set one. This is the fallback for
            # everything else, and it derives rather than picking a constant.
            timeout = (
                derive_discovery_timeout(targets or [])
                if discovery_only
                else DEFAULT_TIMEOUT
            )

        _LOGGER.debug("running: %s %s", self._binary, " ".join(args))
        started = asyncio.get_running_loop().time()

        try:
            proc = await asyncio.create_subprocess_exec(
                self._binary,
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as err:
            raise ScanError(f"could not start nmap: {err}") from err

        timed_out = False
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout)
        except asyncio.TimeoutError:
            timed_out = True
            # TERM then KILL. nmap flushes its XML on TERM, so asking politely
            # first is what turns a timeout into partial DATA rather than
            # nothing at all.
            try:
                proc.terminate()
                stdout, stderr = await asyncio.wait_for(proc.communicate(), 30)
            except (asyncio.TimeoutError, ProcessLookupError):
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                stdout, stderr = b"", b""

        duration = asyncio.get_running_loop().time() - started
        rc = proc.returncode if proc.returncode is not None else -1
        err_text = stderr.decode(errors="replace")[:MAX_STDERR] if stderr else ""

        if not stdout:
            raise ScanError(
                f"nmap produced no output (exit {rc}, {duration:.0f}s)"
                + (f": {err_text.strip()}" if err_text.strip() else "")
            )

        # Parsing is CPU work on a string that can run to megabytes on a deep
        # scan, so it goes to the executor rather than stalling the event loop.
        try:
            hosts = await self._hass.async_add_executor_job(
                _parse_bytes, stdout
            )
        except Exception as err:  # noqa: BLE001 - malformed XML, truncation
            raise ScanError(f"could not parse nmap output: {err}") from err

        complete = rc == 0 and not timed_out
        if not complete:
            _LOGGER.warning(
                "scan finished incomplete (exit %s, timed_out=%s) after %.0fs; "
                "%d hosts observed and kept, absences ignored",
                rc, timed_out, duration, len(hosts),
            )

        return ScanResult(
            hosts=hosts,
            args=args,
            duration=duration,
            returncode=rc,
            complete=complete,
            stderr=err_text,
            timed_out=timed_out,
        )


def _parse_bytes(raw: bytes) -> dict[str, dict[str, Any]]:
    """Decode and parse nmap XML. Runs in an executor thread."""
    return parse_scan(raw.decode(errors="replace"))
