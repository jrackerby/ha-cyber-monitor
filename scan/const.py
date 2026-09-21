"""Constants for the network inventory integration.

NOTHING HERE MAY BE SPECIFIC TO ONE INSTALLATION. This integration is intended
for distribution, so every address, credential and interval is config-entry
data rather than a constant. A hard-coded host is the line that makes an
integration unpublishable, and it is always added "just for now".
"""

from __future__ import annotations

from datetime import timedelta

# MERGE NOTE: was DOMAIN under the standalone network_inventory
# integration. This subpackage no longer owns a manifest/config entry --
# cyber_estate's top-level const.py does. Files that need the REAL owning
# domain (service registration/lookup, device-registry identifiers checked
# by async_remove_config_entry_device) import DOMAIN from ..const instead.
# SCAN_NS is kept only as cosmetic naming text where nothing cross-checks
# it against a live domain.
SCAN_NS = "network_inventory"

CONF_HOST = "host"
CONF_PORT = "port"
CONF_TOKEN = "token"
CONF_VERIFY_SSL = "verify_ssl"
CONF_USE_TLS = "use_tls"

# WHICH END DOES THE SCANNING. One component, two modes, taken from config --
# never two components and never a fork. `agent` talks to a remote scanner over
# HTTP; `local` runs nmap in this container. Both are kept because the migration
# between them has to be reversible: the remote scanner holds the only copy of
# several months of `first_seen` history, and a one-way switch would make
# rolling back cost that history.
CONF_MODE = "mode"
MODE_AGENT = "agent"
MODE_LOCAL = "local"

# Local-mode scanning. TARGETS AND EXCLUDE ARE ALSO OPTIONS KEYS:
# collected in entry.data at setup, editable afterwards in entry.options, and
# read through settings.resolve_settings by everything that needs them.
CONF_TARGETS = "targets"
CONF_EXCLUDE = "exclude"
CONF_DATADIR = "datadir"
CONF_STALE_DAYS = "stale_days"

# the local sweep clocks, as entry.options keys. The unit is IN THE
# KEY because these are stored as bare integers -- a key named `discovery_
# interval` holding 60 cannot be told apart from one holding 60 seconds by
# anything reading the entry later, and the two differ by a factor of sixty.
CONF_DISCOVERY_INTERVAL = "discovery_interval_minutes"
CONF_SERVICE_INTERVAL = "service_interval_minutes"
CONF_SSH_INTERVAL = "ssh_probe_interval_minutes"

# Local-mode SSH reachability probe.
CONF_SSH_ENABLED = "ssh_probe_enabled"
CONF_SSH_KEY = "ssh_key"
CONF_SSH_USERS = "ssh_users"

# options-flow field, mode-independent -- a MAC an operator has explicitly
# decided is accounted for (e.g. a multi-NIC device's ARP-visible interface),
# stored in entry.options so unknown_hosts can reach zero for a real,
# explained case without being silently filtered (see join.py's JoinResult).
CONF_ACKNOWLEDGED_MACS = "acknowledged_macs"

DEFAULT_PORT = 8765
DEFAULT_NAME = "Network Inventory"

# Common conventions, offered as defaults so the usual case is one
# confirmation rather than four lookups. Every one is overridable; none is
# hard-coded anywhere else (see the header).
DEFAULT_SSH_KEY = "/config/.ssh/kiosk_key"
DEFAULT_SSH_USERS = "kiosk, root"
DEFAULT_STALE_DAYS = 30

# How long a host may go unseen before its record is forgotten. Deliberately
# generous: a device switched off for a fortnight is normal, and forgetting it
# destroys `first_seen`, which cannot be recovered by scanning harder.
#
# A FLOOR WITH NO CEILING, and the floor is not a clamp target: a stored value
# under it resolves to the DEFAULT, because saturating to 1 day would forget
# every device switched off since yesterday. `settings.resolve_stale_days`
# carries that reasoning; this constant is only the form's `vol.Range(min=)`.
MIN_STALE_DAYS = 1

# HOW MANY CONSECUTIVE FULL SWEEPS A CONFIGURED TARGET MAY ANSWER WITH NOTHING
# before the integration says so out loud (`scan/coverage.py`). The condition
# being caught is address space that no longer exists -- a re-addressed estate
# left this scanner sweeping three deleted subnets and reporting CLEAN, which
# renders identically to a quiet network (GH-29).
#
# THREE, not one. A subnet whose every host is asleep at 04:00 is an ordinary
# night; three sweeps in a row is not, and at the default hourly discovery
# interval that is a few hours rather than a few weeks. Raising it makes the
# report later, not safer -- the whole failure is that nothing was said at all.
EMPTY_TARGET_SWEEPS = 3

# The agent's API version this client speaks. The agent reports its own
# `schema_version` in every payload and the two are compared on every refresh,
# not merely at setup: an agent can be upgraded underneath a running Home
# Assistant, and a silent shape change is the failure mode this guards.
SUPPORTED_SCHEMA_VERSION = 1

# Scans are hourly at their most frequent, so polling faster only burns
# requests. The agent supports conditional GETs, so a poll between scans
# transfers nothing but headers.
UPDATE_INTERVAL = timedelta(minutes=10)

REQUEST_TIMEOUT = 30

# LOCAL MODE RUNS TWO DIFFERENT SWEEPS ON TWO DIFFERENT CLOCKS, and conflating
# them is the defect this network already paid for once. A liveness sweep is
# cheap and answers "what is on the network"; a service scan is expensive and
# answers "what is it running". Running the cheap one often and the expensive
# one rarely is correct -- what is NOT correct is letting the cheap one's
# freshness stand in for the expensive one's, which is why they are timed,
# stamped and reported separately all the way up to the sensors.
#
# THESE ARE DEFAULTS, NOT THE VALUES. They were module constants, so
# the one thing an operator most often wants to change about a scanner -- how
# often it scans -- was a code edit and a restart, against this file's own
# header. The live values come from settings.resolve_settings; nothing outside
# it reads these three.
DEFAULT_DISCOVERY_INTERVAL_MINUTES = 60
DEFAULT_SERVICE_INTERVAL_MINUTES = 24 * 60

# BOUNDS, ENFORCED TWICE: the form refuses out-of-range input on submit, and
# the resolver clamps whatever it is handed, because a stored value can also
# arrive from a hand-edited .storage file or from bounds that moved between
# versions.
#
# The discovery floor is LOCAL_TICK, below. A sweep cannot be due more often
# than the clock that asks whether it is due, and offering a two-minute
# interval that behaves as five is a setting that lies about itself.
#
# The service ceiling is a fortnight: past that the port data is older than
# DEFAULT_STALE_DAYS makes a host's whole record, so the sweep would be
# scheduled less often than the network forgets what it found.
MIN_DISCOVERY_INTERVAL_MINUTES = 5
MAX_DISCOVERY_INTERVAL_MINUTES = 24 * 60
MIN_SERVICE_INTERVAL_MINUTES = 60
MAX_SERVICE_INTERVAL_MINUTES = 14 * 24 * 60

# The coordinator's own tick in local mode. It does NOT scan on every tick; it
# checks whether either sweep is due. Short enough that an on-demand scan's
# results reach the entities promptly.
LOCAL_TICK = timedelta(minutes=5)

# The SSH probe runs against every host seen offering ssh. Kept well apart from
# the scan clocks: it is cheap, but it authenticates against real hosts, and
# doing that every five minutes would fill authentication logs network-wide --
# which is also why its floor is an hour rather than LOCAL_TICK. Configurable
# on the same terms as the sweeps above.
DEFAULT_SSH_INTERVAL_MINUTES = 6 * 60
MIN_SSH_INTERVAL_MINUTES = 60
MAX_SSH_INTERVAL_MINUTES = 7 * 24 * 60

# Scan profiles the agent will accept. Mirrored from the agent's own allowlist
# rather than discovered, because a button for a profile the agent rejects is a
# control that looks live and does nothing. The agent validates independently;
# this copy exists so the UI cannot offer an action that cannot succeed.
PROFILES: tuple[str, ...] = ("discovery", "standard", "deep")

# What an endpoint reports when nmap could not fingerprint it. A BLANK IS NOT
# ACCEPTABLE HERE: an empty state is indistinguishable from a sensor that
# failed to read, and "we looked and could not tell" is a different fact from
# "we do not know whether we looked".
OS_UNDETERMINED = "Undetermined"

# Home Assistant refuses a state longer than 255 characters, and an nmap
# osmatch string can run long when it lists alternatives. Truncated with a
# marker so a clipped value cannot read as a complete one.
MAX_STATE_LEN = 255

# Entity attributes are capped HERE rather than by asking the recorder to
# exclude the entity. Excluding stops history for the value as well as the
# detail, which quietly removes the ability to ask "how long has this been
# true" of the one number that matters. A cap keeps the trend and drops only
# the long tail.
MAX_DETAIL = 25

# How stale port data may get before the port-scanning profile is considered
# to have stopped running. The discovery sweep runs hourly and observes no
# ports at all; only the deeper profiles do, and those are typically nightly.
# Two days therefore clears one missed nightly run without hiding a dead one.
PORT_DATA_STALE_AFTER = timedelta(days=2)
