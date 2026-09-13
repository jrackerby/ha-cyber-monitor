"""Config flow for cyber_estate -- merge of nvd_estate's API-key
step and network_inventory's local/agent scan setup into one sequential
flow, producing ONE config entry for all three subsystems.

ORDER IS DELIBERATE: the NVD key first, then the scan-mode menu. Both
halves' original validation is preserved verbatim (the same NVD probe
against a known CVE, the same nmap-binary / agent-connectivity checks) --
only the sequencing and the final async_create_entry are new.

REAUTH IS API-KEY ONLY. If the key stops working, cve/coordinator.py calls
entry.async_start_reauth(hass) itself (unchanged from the standalone
integration); async_step_reauth_confirm here updates just CONF_API_KEY via
data_updates, which merges into entry.data rather than replacing it, so a
reauth never touches the scan half of the entry.

THREE WAYS TO CHANGE A RUNNING ENTRY, AND THE SPLIT BETWEEN THEM IS BY WHERE
THE VALUE IS READ, not by how important it looks:

  * OPTIONS (`CyberEstateOptionsFlow`) -- scan scope, the sweep clocks, the
    acknowledged MACs. The coordinator re-reads all three off the entry on
    every tick, so these change live, with no reload and without touching the
    inventory store that holds `first_seen` for the whole network.
  * RECONFIGURE (`async_step_reconfigure`) -- the NVD key, the agent address
    and token, the nmap data directory, the SSH settings. Every one of these
    is read ONCE during setup, so a change is inert until the entry reloads,
    and this flow reloads.
  * REAUTH -- the NVD key alone, started by the coordinator rather than by a
    person, when the key it has stops being accepted.

NO KEY APPEARS IN TWO OF THEM. `resolve_settings` reads targets, exclude and
the intervals out of `entry.options` ahead of `entry.data`, so a reconfigure
form carrying targets would write a key the coordinator has stopped consulting
-- the same value with two editors and one of them silently inert.
"""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import (
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
)

from .alerting import (
    CONF_CLEAR_OBSERVATIONS,
    CONF_CONFIRM_OBSERVATIONS,
    CONF_MAX_EVENTS_PER_HOUR,
    CONF_MIN_HOLD_MINUTES,
    MAX_EVENTS_PER_HOUR,
    MAX_HOLD_MINUTES,
    MAX_OBSERVATIONS,
    MIN_EVENTS_PER_HOUR,
    MIN_HOLD_MINUTES,
    MIN_OBSERVATIONS,
    resolve_policy,
)
from .const import DOMAIN
from .cve.const import CONF_API_KEY, NVD_CVE_URL
from .scan.api import (
    CannotConnect,
    InvalidAuth,
    NetworkInventoryClient,
    UnsupportedSchema,
)
from .scan.const import (
    CONF_ACKNOWLEDGED_MACS,
    CONF_DATADIR,
    CONF_DISCOVERY_INTERVAL,
    CONF_EXCLUDE,
    CONF_HOST,
    CONF_MODE,
    CONF_PORT,
    CONF_SERVICE_INTERVAL,
    CONF_SSH_ENABLED,
    CONF_SSH_INTERVAL,
    CONF_SSH_KEY,
    CONF_SSH_USERS,
    CONF_STALE_DAYS,
    CONF_TARGETS,
    CONF_TOKEN,
    CONF_USE_TLS,
    CONF_VERIFY_SSL,
    DEFAULT_PORT,
    DEFAULT_SSH_KEY,
    DEFAULT_SSH_USERS,
    DEFAULT_STALE_DAYS,
    MAX_DISCOVERY_INTERVAL_MINUTES,
    MAX_SERVICE_INTERVAL_MINUTES,
    MAX_SSH_INTERVAL_MINUTES,
    MIN_DISCOVERY_INTERVAL_MINUTES,
    MIN_SERVICE_INTERVAL_MINUTES,
    MIN_SSH_INTERVAL_MINUTES,
    MIN_STALE_DAYS,
    MODE_AGENT,
    MODE_LOCAL,
)
from .scan.join import normalise_mac
from .scan.options import DEFAULT_DATADIR, InvalidScanRequest, validate_target
from .scan.scanner import find_nmap
from .scan.settings import resolve_settings, split_list

_LOGGER = logging.getLogger(__name__)

# A cheap, always-present CVE. Any CVE id works; what is being tested is
# whether NVD accepts the key, not what it says about this vulnerability.
_PROBE_CVE = "CVE-2022-0492"

STEP_API_KEY = vol.Schema({vol.Required(CONF_API_KEY): str})

STEP_AGENT = vol.Schema(
    {
        vol.Required(CONF_HOST): str,
        vol.Required(CONF_PORT, default=DEFAULT_PORT): int,
        vol.Required(CONF_TOKEN): str,
        vol.Optional(CONF_USE_TLS, default=False): bool,
        vol.Optional(CONF_VERIFY_SSL, default=True): bool,
    }
)

STEP_LOCAL = vol.Schema(
    {
        vol.Required(CONF_TARGETS): str,
        vol.Optional(CONF_EXCLUDE, default=""): str,
        vol.Optional(CONF_DATADIR, default=DEFAULT_DATADIR): str,
        vol.Optional(CONF_STALE_DAYS, default=DEFAULT_STALE_DAYS): vol.All(
            int, vol.Range(min=MIN_STALE_DAYS)
        ),
        vol.Optional(CONF_SSH_ENABLED, default=True): bool,
        vol.Optional(CONF_SSH_KEY, default=DEFAULT_SSH_KEY): str,
        vol.Optional(CONF_SSH_USERS, default=DEFAULT_SSH_USERS): str,
    }
)


def _validated_scope(user_input: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Split and validate the target/exclude fields. Raises InvalidScanRequest.

    ONE VALIDATOR FOR BOTH FLOWS. Setup collects these fields and the
    options flow edits them afterwards, and a second copy of this parsing is
    exactly how the two end up disagreeing about what a trailing comma or a
    bare hostname means -- the initial form would refuse a value the options
    form accepted, or worse, the reverse. `validate_target` is the same
    function `build_args` runs against every target immediately before nmap
    sees it, so a value that passes here cannot be rejected later for being
    the wrong shape.
    """
    targets = split_list(user_input.get(CONF_TARGETS))
    excludes = split_list(user_input.get(CONF_EXCLUDE))
    if not targets:
        raise InvalidScanRequest("no targets given")
    for value in targets + excludes:
        validate_target(value)
    return targets, excludes


def _count(minimum: int, maximum: int, unit: str):
    """A bounded whole number with a unit label. Same shape as `_minutes`,
    for the same reason: the bounds are the module's, never restated."""
    return vol.All(
        NumberSelector(
            NumberSelectorConfig(
                min=minimum,
                max=maximum,
                step=1,
                mode=NumberSelectorMode.BOX,
                unit_of_measurement=unit,
            )
        ),
        vol.Coerce(int),
    )


def _minutes(minimum: int, maximum: int):
    """A whole number of minutes, bounded, rendered as a number box.

    The bounds are the const.py ones rather than repeated here, so the form
    and `settings.resolve_settings`'s clamp cannot disagree about what is
    acceptable -- a form that accepted 2 minutes while the resolver clamped it
    to 5 would report a schedule it was not keeping.
    """
    return vol.All(
        NumberSelector(
            NumberSelectorConfig(
                min=minimum,
                max=maximum,
                step=1,
                mode=NumberSelectorMode.BOX,
                unit_of_measurement="minutes",
            )
        ),
        vol.Coerce(int),
    )


async def _validate_nvd_key(hass, api_key) -> str | None:
    """Return None if the key works, else an error slug for the form.

    THE KEY IS VALIDATED BEFORE IT IS ACCEPTED. An unauthenticated NVD
    request still succeeds (5 requests/30s instead of 50), so a typo'd key
    does NOT announce itself by breaking -- it announces itself by
    rate-limiting hours later, under load, looking like an NVD outage.
    """
    session = async_get_clientsession(hass)
    try:
        async with session.get(
            NVD_CVE_URL,
            params={"cveId": _PROBE_CVE},
            headers={"apiKey": api_key, "User-Agent": "ha-cyber-monitor/1.0"},
            timeout=30,
        ) as resp:
            if resp.status in (401, 403):
                return "invalid_auth"
            if resp.status != 200:
                return "cannot_connect"
            data = await resp.json(content_type=None)
    except Exception:  # noqa: BLE001 - any failure is a failed validation
        return "cannot_connect"

    # A 200 carrying no result for a CVE that certainly exists means we are
    # not talking to the API we think we are -- a captive portal or a proxy.
    if not (data.get("vulnerabilities") or []):
        return "cannot_connect"
    return None


class CyberEstateConfigFlow(ConfigFlow, domain=DOMAIN):
    """NVD key, then scan mode, then one combined entry."""

    VERSION = 1

    def __init__(self) -> None:
        self._api_key_data: dict[str, Any] = {}

    @staticmethod
    @callback
    def async_get_options_flow(entry: ConfigEntry) -> OptionsFlow:
        return CyberEstateOptionsFlow()

    # -- step 1: NVD API key -------------------------------------------

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            # single_config_entry in manifest.json already enforces this;
            # kept as defense-in-depth, matching the pattern the merged
            # subsystems' own standalone flows used.
            await self.async_set_unique_id(DOMAIN)
            self._abort_if_unique_id_configured()

            err = await _validate_nvd_key(self.hass, user_input[CONF_API_KEY])
            if err:
                errors["base"] = err
            else:
                self._api_key_data = user_input
                return await self.async_step_scan_mode()

        return self.async_show_form(
            step_id="user", data_schema=STEP_API_KEY, errors=errors
        )

    # -- step 2: which end does the scanning -----------------------------

    async def async_step_scan_mode(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """THE TWO MODES NEED DISJOINT INFORMATION -- one wants an address
        and a token, the other wants subnets and a key path -- so a single
        form would show every field and mark most of them optional,
        leaving the operator to work out which half applies to them."""
        return self.async_show_menu(
            step_id="scan_mode", menu_options=[MODE_LOCAL, MODE_AGENT]
        )

    async def async_step_local(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Scan from Home Assistant itself."""
        errors: dict[str, str] = {}

        if user_input is not None:
            # VALIDATED HERE, not at first scan. A target that nmap will
            # refuse should be refused while the person who typed it is
            # still looking at the field.
            try:
                _validated_scope(user_input)
            except InvalidScanRequest as err:
                _LOGGER.debug("rejected target: %s", err)
                errors[CONF_TARGETS] = "invalid_target"

            if not errors:
                binary = await self.hass.async_add_executor_job(find_nmap)
                if not binary:
                    errors["base"] = "no_nmap"

            if not errors:
                return self.async_create_entry(
                    title="Cyber Monitor",
                    data={
                        **self._api_key_data,
                        **user_input,
                        CONF_MODE: MODE_LOCAL,
                    },
                )

        return self.async_show_form(
            step_id=MODE_LOCAL, data_schema=STEP_LOCAL, errors=errors
        )

    async def async_step_agent(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            host = user_input[CONF_HOST].strip()
            port = user_input[CONF_PORT]

            client = NetworkInventoryClient(
                session=async_get_clientsession(self.hass),
                host=host,
                port=port,
                token=user_input[CONF_TOKEN],
                use_tls=user_input.get(CONF_USE_TLS, False),
                verify_ssl=user_input.get(CONF_VERIFY_SSL, True),
            )

            try:
                await client.async_verify()
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except UnsupportedSchema as err:
                _LOGGER.error("Unsupported agent schema: %s", err)
                errors["base"] = "unsupported_schema"
            except CannotConnect as err:
                _LOGGER.debug("Cannot connect to agent: %s", err)
                errors["base"] = "cannot_connect"
            except Exception:  # noqa: BLE001 - config flows must not crash
                _LOGGER.exception("Unexpected error verifying agent")
                errors["base"] = "unknown"
            else:
                return self.async_create_entry(
                    title="Cyber Monitor",
                    data={
                        **self._api_key_data,
                        **user_input,
                        CONF_HOST: host,
                        CONF_MODE: MODE_AGENT,
                    },
                )

        return self.async_show_form(
            step_id=MODE_AGENT, data_schema=STEP_AGENT, errors=errors
        )

    # -- reconfigure: the entry.data the options flow will not touch ------

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Edit the stored setup values in place, without rebuilding the entry.

        WHAT IS HERE IS EXACTLY WHAT THE OPTIONS FLOW REFUSES, and the split is
        not stylistic. `resolve_settings` reads targets, exclude and the three
        sweep clocks out of `entry.options` FIRST and falls back to `entry.data`,
        so a form here offering targets would edit a key the coordinator stops
        consulting the moment the options flow has ever saved a scope -- a
        control that looks live and does nothing, which is the failure that
        module's own header is written to prevent. Those five keys have a live
        editor already (Configure -> Networks to scan / How often to scan). This
        step takes the rest: the NVD key, the agent connection, and the local
        collector settings, none of which the options flow touches.

        IT RELOADS AND THE OPTIONS FLOW DOES NOT, also deliberately. Every value
        here is read once during setup -- the agent client is constructed from
        the address and token, the nmap binary and data directory are resolved
        then, the SSH prober is wired then -- so a change is inert until the
        entry restarts. `async_update_reload_and_abort` is the honest ending for
        a form whose values only take effect that way.
        """
        entry = self._get_reconfigure_entry()
        if entry.data.get(CONF_MODE) == MODE_LOCAL:
            return await self.async_step_reconfigure_local(user_input)
        return await self.async_step_reconfigure_agent(user_input)

    async def _revalidated_key(
        self, entry, user_input: dict[str, Any]
    ) -> str | None:
        """Probe the NVD key only when it actually changed.

        An unchanged key is not re-probed, and that is not laziness: NVD being
        unreachable would otherwise refuse a form somebody opened to fix the
        agent address, which is both unrelated and, quite possibly, the reason
        they are here. A key that has NOT been edited was already validated when
        it was accepted, and reauth exists for the case where it stops working.
        """
        key = user_input[CONF_API_KEY]
        if key == entry.data.get(CONF_API_KEY):
            return None
        return await _validate_nvd_key(self.hass, key)

    async def async_step_reconfigure_local(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        entry = self._get_reconfigure_entry()
        errors: dict[str, str] = {}

        if user_input is not None:
            err = await self._revalidated_key(entry, user_input)
            if err:
                errors["base"] = err
            else:
                # The data directory is NOT refused when it is missing, matching
                # setup exactly. `_async_setup_local` logs loudly and carries on
                # -- port scanning still works without the script engine -- and a
                # form that refused here while setup accepted would be the second
                # validator disagreeing with the first, which is the trap
                # `_validated_scope` exists to avoid on the other fields.
                return self.async_update_reload_and_abort(
                    entry, data_updates=user_input
                )

        current = entry.data
        return self.async_show_form(
            step_id="reconfigure_local",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_API_KEY, default=current.get(CONF_API_KEY, "")
                    ): str,
                    vol.Optional(
                        CONF_DATADIR,
                        default=current.get(CONF_DATADIR, DEFAULT_DATADIR),
                    ): str,
                    vol.Optional(
                        CONF_STALE_DAYS,
                        default=current.get(CONF_STALE_DAYS, DEFAULT_STALE_DAYS),
                    ): vol.All(int, vol.Range(min=MIN_STALE_DAYS)),
                    vol.Optional(
                        CONF_SSH_ENABLED,
                        default=current.get(CONF_SSH_ENABLED, True),
                    ): bool,
                    vol.Optional(
                        CONF_SSH_KEY, default=current.get(CONF_SSH_KEY, DEFAULT_SSH_KEY)
                    ): str,
                    vol.Optional(
                        CONF_SSH_USERS,
                        default=current.get(CONF_SSH_USERS, DEFAULT_SSH_USERS),
                    ): str,
                }
            ),
            errors=errors,
        )

    async def async_step_reconfigure_agent(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        entry = self._get_reconfigure_entry()
        errors: dict[str, str] = {}

        if user_input is not None:
            err = await self._revalidated_key(entry, user_input)
            if err:
                errors["base"] = err

            host = user_input[CONF_HOST].strip()
            if not errors:
                # THE NEW CREDENTIAL IS EXERCISED ON THE CHANNEL IT WILL RUN ON,
                # here rather than at the next refresh. A reconfigure that stored
                # an unreachable address and reloaded would leave the entry in
                # setup_retry with the dialog already closed, and the reason only
                # in the log.
                client = NetworkInventoryClient(
                    session=async_get_clientsession(self.hass),
                    host=host,
                    port=user_input[CONF_PORT],
                    token=user_input[CONF_TOKEN],
                    use_tls=user_input.get(CONF_USE_TLS, False),
                    verify_ssl=user_input.get(CONF_VERIFY_SSL, True),
                )
                try:
                    await client.async_verify()
                except InvalidAuth:
                    errors["base"] = "invalid_auth"
                except UnsupportedSchema as err_schema:
                    _LOGGER.error("Unsupported agent schema: %s", err_schema)
                    errors["base"] = "unsupported_schema"
                except CannotConnect as err_conn:
                    _LOGGER.debug("Cannot connect to agent: %s", err_conn)
                    errors["base"] = "cannot_connect"
                except Exception:  # noqa: BLE001 - config flows must not crash
                    _LOGGER.exception("Unexpected error verifying agent")
                    errors["base"] = "unknown"

            if not errors:
                return self.async_update_reload_and_abort(
                    entry, data_updates={**user_input, CONF_HOST: host}
                )

        current = entry.data
        return self.async_show_form(
            step_id="reconfigure_agent",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_API_KEY, default=current.get(CONF_API_KEY, "")
                    ): str,
                    vol.Required(CONF_HOST, default=current.get(CONF_HOST, "")): str,
                    vol.Required(
                        CONF_PORT, default=current.get(CONF_PORT, DEFAULT_PORT)
                    ): int,
                    vol.Required(CONF_TOKEN, default=current.get(CONF_TOKEN, "")): str,
                    vol.Optional(
                        CONF_USE_TLS, default=current.get(CONF_USE_TLS, False)
                    ): bool,
                    vol.Optional(
                        CONF_VERIFY_SSL, default=current.get(CONF_VERIFY_SSL, True)
                    ): bool,
                }
            ),
            errors=errors,
        )

    # -- NVD key rotation / reauth ---------------------------------------

    async def async_step_reauth(self, entry_data) -> ConfigFlowResult:
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            err = await _validate_nvd_key(self.hass, user_input[CONF_API_KEY])
            if err:
                errors["base"] = err
            else:
                # data_updates MERGES into entry.data -- the scan half of
                # the entry is untouched.
                return self.async_update_reload_and_abort(
                    self._get_reauth_entry(),
                    data_updates={CONF_API_KEY: user_input[CONF_API_KEY]},
                )

        return self.async_show_form(
            step_id="reauth_confirm", data_schema=STEP_API_KEY, errors=errors
        )


class CyberEstateOptionsFlow(OptionsFlow):
    """Everything about a running entry that is safe to change in place.

    NARROW AND ADDITIVE, ONE CONCERN PER STEP. It began as a single
    acknowledged-MACs field, deliberately not touching `entry.data`, and it
    keeps that shape: each step writes the handful of keys it owns and merges
    them over whatever is already stored. A wholesale-data options flow -- one
    form carrying every setting -- creates the "resubmit everything or lose a
    field" trap this network has paid for elsewhere, and it would put the NVD
    key and the agent token on a form nobody opened to change them.

    THE MERGE IS LOAD BEARING. `async_create_entry(data=...)` REPLACES the
    options mapping wholesale, so a step that returns only its own keys
    silently deletes every other step's. Harmless while there was exactly one
    step and latent from then onwards; the moment a second step was added,
    saving a subnet list would have cleared the acknowledged MACs and put
    `unknown_hosts` back up by however many had been acknowledged -- a number
    moving on its own, with no edit to point at.

    NOTHING HERE RELOADS THE ENTRY. The coordinator re-reads scope and
    schedule off the entry on every tick (coordinator.settings) and the
    acknowledged MACs on every refresh, so a saved change is live on the next
    tick without restarting three subsystems -- and, critically, without
    touching the inventory store, which holds `first_seen` for the whole
    inventory and is the reason "delete the entry and set it up again" was never
    an acceptable way to add a subnet.

    SCOPE AND SCHEDULE ARE LOCAL MODE ONLY, and are not offered in agent mode
    rather than offered and ignored. In agent mode the targets live in the
    scanner host's own `scan.sh` and the schedule in its
    `nmap-scan@<profile>.timer` units; the agent's v1 API serves
    /inventory, /status, /health, /scan and /schedule, and /schedule takes
    {profile, enabled} only. There is no endpoint an interval could be sent
    to, so a form here would be a control that looks live and does nothing --
    the exact failure the pinned profile list and the option vocabulary are
    both written to prevent.
    """

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Pick a concern -- or, in agent mode, go straight to the one that
        applies, rather than showing a menu with a single item on it."""
        # Alerting is mode-independent: it debounces the join's answer, which
        # agent and local mode produce identically. So agent mode has two
        # concerns now and gets a menu rather than a jump.
        if self.config_entry.data.get(CONF_MODE) != MODE_LOCAL:
            return self.async_show_menu(
                step_id="init", menu_options=["acknowledged_macs", "alerting"]
            )
        return self.async_show_menu(
            step_id="init",
            menu_options=["scan_scope", "schedule", "acknowledged_macs", "alerting"],
        )

    def _save(self, updates: dict[str, Any]) -> ConfigFlowResult:
        """Write one step's keys over the stored options, keeping the rest."""
        return self.async_create_entry(
            data={**self.config_entry.options, **updates}
        )

    # -- what gets scanned ---------------------------------------------------

    async def async_step_scan_scope(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Edit the networks to scan and the addresses to leave alone.

        STORED AS A LIST, NOT THE RAW STRING. The text field is a convenience
        for typing; what the coordinator scans is the parsed, validated list,
        and keeping the unparsed string would leave a second representation of
        the same setting for someone to read later and split differently.
        """
        errors: dict[str, str] = {}
        settings = resolve_settings(
            self.config_entry.data, self.config_entry.options
        )

        if user_input is not None:
            try:
                targets, excludes = _validated_scope(user_input)
            except InvalidScanRequest as err:
                _LOGGER.debug("rejected target: %s", err)
                # ON THE FIELD, not on the form. `base` would put "that is not
                # an address" under the dialog title with both fields looking
                # equally innocent.
                errors[CONF_TARGETS] = "invalid_target"
            else:
                return self._save(
                    {CONF_TARGETS: targets, CONF_EXCLUDE: excludes}
                )

        # Redisplayed from what was TYPED when there is an error, so a typo is
        # corrected in place rather than reverting to the stored value and
        # making the operator retype the whole line.
        current_targets = (
            user_input.get(CONF_TARGETS)
            if user_input is not None
            else ", ".join(settings.targets)
        )
        current_exclude = (
            user_input.get(CONF_EXCLUDE)
            if user_input is not None
            else ", ".join(settings.exclude)
        )
        return self.async_show_form(
            step_id="scan_scope",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_TARGETS, default=current_targets): str,
                    vol.Optional(CONF_EXCLUDE, default=current_exclude): str,
                }
            ),
            errors=errors,
        )

    # -- how often it gets scanned -------------------------------------------

    async def async_step_schedule(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Edit the local sweep clocks.

        TWO SWEEPS AND A PROBE, WHICH IS WHAT LOCAL MODE ACTUALLY HAS. The
        `PROFILES` tuple names three -- discovery, standard, deep -- because it
        mirrors the AGENT's allowlist, and the agent has three timer units. The
        local coordinator schedules two: `_run_discovery` and
        `_run_service_scan`. `deep` exists locally as an on-demand button only,
        with no clock to configure, so offering a deep interval here would be a
        field with nothing behind it. The SSH probe is the third clock and is
        listed because it authenticates against real hosts on a timer, which is
        a frequency someone will want to change for a reason the scan sweeps do
        not share.

        The bounds are enforced by the selector on submit AND by the resolver
        on read; neither is redundant, because only one of them sees a value
        that arrived from a hand-edited .storage file.
        """
        settings = resolve_settings(
            self.config_entry.data, self.config_entry.options
        )

        if user_input is not None:
            return self._save(
                {
                    CONF_DISCOVERY_INTERVAL: user_input[CONF_DISCOVERY_INTERVAL],
                    CONF_SERVICE_INTERVAL: user_input[CONF_SERVICE_INTERVAL],
                    CONF_SSH_INTERVAL: user_input[CONF_SSH_INTERVAL],
                }
            )

        return self.async_show_form(
            step_id="schedule",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_DISCOVERY_INTERVAL,
                        default=int(
                            settings.discovery_interval.total_seconds() // 60
                        ),
                    ): _minutes(
                        MIN_DISCOVERY_INTERVAL_MINUTES,
                        MAX_DISCOVERY_INTERVAL_MINUTES,
                    ),
                    vol.Required(
                        CONF_SERVICE_INTERVAL,
                        default=int(settings.service_interval.total_seconds() // 60),
                    ): _minutes(
                        MIN_SERVICE_INTERVAL_MINUTES,
                        MAX_SERVICE_INTERVAL_MINUTES,
                    ),
                    vol.Required(
                        CONF_SSH_INTERVAL,
                        default=int(settings.ssh_interval.total_seconds() // 60),
                    ): _minutes(
                        MIN_SSH_INTERVAL_MINUTES, MAX_SSH_INTERVAL_MINUTES
                    ),
                }
            ),
        )

    # -- when a finding becomes an alert, and how often the bus hears it ----

    async def async_step_alerting(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Debounce, hold and event-rate for the two security flags.

        FOUR NUMBERS, ONE RESOLVER. Defaults shown here come from
        `alerting.resolve_policy` over the stored options, which is also what
        the monitor runs on, so the form cannot show one number while the
        flag keeps another. Read live by the monitor on every observation --
        a lowered confirm count takes effect on the next sweep, no reload.

        The bounds are enforced by the selector on submit AND by the resolver
        on read, for the reason `schedule` gives: only one of them sees a
        value that arrived from a hand-edited .storage file.
        """
        policy = resolve_policy(self.config_entry.options)

        if user_input is not None:
            return self._save(
                {
                    CONF_CONFIRM_OBSERVATIONS: user_input[CONF_CONFIRM_OBSERVATIONS],
                    CONF_CLEAR_OBSERVATIONS: user_input[CONF_CLEAR_OBSERVATIONS],
                    CONF_MIN_HOLD_MINUTES: user_input[CONF_MIN_HOLD_MINUTES],
                    CONF_MAX_EVENTS_PER_HOUR: user_input[CONF_MAX_EVENTS_PER_HOUR],
                }
            )

        return self.async_show_form(
            step_id="alerting",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_CONFIRM_OBSERVATIONS,
                        default=policy.confirm_observations,
                    ): _count(MIN_OBSERVATIONS, MAX_OBSERVATIONS, "scans"),
                    vol.Required(
                        CONF_CLEAR_OBSERVATIONS,
                        default=policy.clear_observations,
                    ): _count(MIN_OBSERVATIONS, MAX_OBSERVATIONS, "scans"),
                    vol.Required(
                        CONF_MIN_HOLD_MINUTES,
                        default=int(policy.min_hold_seconds // 60),
                    ): _minutes(MIN_HOLD_MINUTES, MAX_HOLD_MINUTES),
                    vol.Required(
                        CONF_MAX_EVENTS_PER_HOUR,
                        default=policy.max_events_per_hour,
                    ): _count(MIN_EVENTS_PER_HOUR, MAX_EVENTS_PER_HOUR, "events"),
                }
            ),
        )

    # -- acknowledge a MAC `unknown_hosts` cannot otherwise clear ----

    async def async_step_acknowledged_macs(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """A MAC an operator has looked at and decided is accounted for.

        Read live by the coordinator every refresh (`_acknowledged_macs()`),
        so acking a host takes effect on the next tick, no reload required.
        """
        errors: dict[str, str] = {}
        current = self.config_entry.options.get(CONF_ACKNOWLEDGED_MACS, [])

        if user_input is not None:
            raw = split_list(user_input.get(CONF_ACKNOWLEDGED_MACS, ""))
            normalised: list[str] = []
            bad: list[str] = []
            for value in raw:
                mac = normalise_mac(value)
                if mac is None:
                    bad.append(value)
                else:
                    normalised.append(mac)
            if bad:
                errors[CONF_ACKNOWLEDGED_MACS] = "invalid_mac"
            else:
                return self._save({CONF_ACKNOWLEDGED_MACS: normalised})

        return self.async_show_form(
            step_id="acknowledged_macs",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_ACKNOWLEDGED_MACS, default=", ".join(current)
                    ): str,
                }
            ),
            errors=errors,
        )
