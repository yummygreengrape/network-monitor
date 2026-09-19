"""English message catalogue.

Register
  - Findings and status lines are terse and declarative. No first or second
    person, no hedging filler, no exclamation.
    "Gateway round-trip time rose to 112ms (average 20ms)."
  - Questions and instructions addressed to the reader stay as such.
  - State observations plainly; mark interpretation as interpretation
    ("suspected", "likely", "may be").

Names and format placeholders must match ko.py exactly.
tests/test_messages.py enforces that.
"""
from __future__ import annotations

# ─────────────────────────────────────────── Findings: link layer (L2)
GW_MAC_CHANGED = ("Gateway MAC changed while staying on the same network. "
                  "ARP spoofing or an access point swap is suspected.")
GW_MAC_CHANGED_MOVED = "Gateway MAC changed, but the network changed at the same time."
DUPLICATE_IP = "IP conflict detected (Duplicate IP seen counter rose by %d)."
HINT_ARP_LOG_OFF = ("Kernel ARP warnings are off, so MAC substitutions are recorded "
                    "nowhere. `sudo sysctl -w %s=1` records the old and new MAC together "
                    "and catches substitutions that happen between polls. Resets on reboot.")
ARP_MAC_SUBSTITUTED = ("The kernel recorded %d ARP entry MAC substitution(s), including "
                       "changes that happen between polls and leave no trace in the cache.")
ARP_MAC_SUBSTITUTED_GW = ("The kernel recorded %d ARP entry MAC substitution(s), and the "
                          "gateway was among them. This is the classic shape of ARP spoofing.")
ARP_PERMANENT_DENIED = ("The kernel refused %d attempt(s) to modify a permanent ARP entry. "
                        "Normal operation does not produce this.")
ARP_REPLY_SPIKE = "ARP replies received rose to %.0fx the usual rate (%d per cycle, average %.1f)."
SHARED_MAC = ("One MAC is holding %d addresses at once. This is the shape of ARP "
              "spoofing, but a router answering by proxy looks the same.")

# ─────────────────────────────────────────── Findings: DHCP
DHCP_SERVER_CHANGED = ("DHCP server changed while staying on the same network. "
                       "This is the classic shape of a rogue DHCP server.")
DHCP_SERVER_CHANGED_MOVED = "DHCP server changed, but the network changed at the same time."
DHCP_ROUTER_CHANGED = "The default router advertised by DHCP changed."
DHCP_DNS_CHANGED = ("The DNS servers advertised by DHCP changed. This can be the first "
                    "step of name resolution hijacking.")
DHCP_LEASE_RENEWED = ("DHCP lease restarted. This can be a periodic renewal or a "
                      "reconnection; this cycle alone cannot tell them apart.")
DHCP_LEASE_RENEWED_AFTER_LINK = ("DHCP lease restarted, right after the link dropped and "
                                 "came back.")
OWN_IP_CHANGED = "The IP address assigned to this machine changed."

# ─────────────────────────────────────────── Findings: DNS and proxy
RESOLVER_CHANGED = "System DNS resolvers changed."
DNS_LOCAL_PROXY_ON = "DNS now goes through a local proxy."
DNS_LOCAL_PROXY_OFF = "DNS no longer goes through a local proxy."
PROXY_ENABLED = "Proxy turned on (%s). Traffic now passes through a third party."
PROXY_SETTINGS_CHANGED = "Proxy settings changed."

# ─────────────────────────────────────────── Findings: routing
DEFAULT_ROUTE_CHANGED = "IPv4 default route changed."
IPV6_DEFAULT_ROUTE_APPEARED = ("An IPv6 default route appeared on a physical interface. "
                               "Someone on this network may have sent a router "
                               "advertisement (rogue RA).")
IPV6_ROUTER_APPEARED = "New IPv6 router in the neighbour table (%d)."
ROUTES_OUTSIDE_TUNNEL = ("%d new route(s) appeared on a non-tunnel interface (%s). Traffic "
                         "for those prefixes leaves outside the VPN. This change is not "
                         "visible in the default route alone.")
DHCP_STATIC_ROUTES = ("DHCP offered %d static route(s). This is rare on home networks. "
                      "It is also the means by which routes more specific than a VPN's "
                      "default are pushed to bypass the tunnel (CVE-2024-3661).")
DHCP_STATIC_ROUTES_UNREAD = ("DHCP offered a static-route option whose format could not be "
                             "decoded. This does not mean there are no routes.")
TUNNEL_BYPASS_ROUTE = ("%d prefix(es) offered by DHCP egress through a non-tunnel interface. "
                       "Traffic for those prefixes is outside the VPN. This can be a "
                       "split-tunnel configuration or route injection - this tool cannot tell.")
MULTIPLE_DEFAULT_ROUTES = "%d IPv4 default routes. Normal while a VPN is up."

# ─────────────────────────────────────────── Findings: Wi-Fi
WIFI_SECURITY_DOWNGRADE = ("Wi-Fi encryption weakened (%s → %s). This can mean being lured "
                           "onto a weaker access point using the same name.")
WIFI_SECURITY_DOWNGRADE_OTHER = ("Wi-Fi encryption weakened (%s → %s). This was a move to a "
                                 "differently named network, so a same-name lure is unlikely.")
WIFI_SECURITY_DOWNGRADE_UNKNOWN = ("Wi-Fi encryption weakened (%s → %s). The network name could "
                                   "not be read, so a same-name lure cannot be ruled in or out.")
WIFI_SECURITY_CHANGED = "Wi-Fi encryption changed (%s → %s)."
EVIL_TWIN_CANDIDATE = ("Access point, gateway and DHCP all changed under the same SSID. "
                       "Normal roaming usually keeps the same gateway.")
WIFI_BAND_CHANGED = ("Wi-Fi band changed from %sGHz to %sGHz. This is not roaming - the "
                     "client moved to a different radio on the same router.")
WIFI_BAND_CHANGED_RATE = ("Wi-Fi band changed from %sGHz to %sGHz. The transmit-rate ceiling "
                          "went from %d to %d Mbps. This is not roaming - it is a different radio.")
WIFI_ROAM = "Access point changed within the same SSID (roaming)."
WIFI_NETWORK_SWITCHED = "Moved to a different Wi-Fi network."
WIFI_AP_CHANGED_NAME_UNKNOWN = ("Access point changed. The network name could not be read, so "
                                "roaming and a move to another network cannot be told apart.")
WIFI_LINK_CHANGED = "Wi-Fi link status changed (%s → %s)."

# ─────────────────────────────────────────── Findings: connection quality
GATEWAY_ICMP_SILENT = ("This gateway does not answer ICMP. ARP is healthy, so this is not "
                       "a fault. Reachability now judged from ARP instead.")
GATEWAY_ICMP_OK = "Gateway answers ICMP. Reachability and latency judged from ping."
FIRST_HOP_UNREACHABLE = "First hop silent %d cycles in a row (by %s). %s"
FIRST_HOP_CAUSE_WEAK = "Wireless signal is weak (RSSI %d dBm) - likely a wireless problem."
FIRST_HOP_CAUSE_STRONG = ("Wireless signal is fine (RSSI %d dBm), so radio trouble is unlikely. "
                          "The cause cannot be told from this observation alone.")
FIRST_HOP_CAUSE_WIRED = "Wired connection. The cause cannot be told from this observation alone."
FIRST_HOP_CAUSE_UNKNOWN = "Signal strength unavailable, so the cause cannot be told."
FIRST_HOP_RECOVERED = "First hop answering again (after %d failures, by %s)."
FIRST_HOP_BRIEF_GAP = "First hop silent %d cycles in a row, then answering again (by %s, below the alert threshold)."
LATENCY_SPIKE = "Gateway round-trip time rose to %.0fms (average %.0fms)."
MEASUREMENT_GAP = "Measurement stopped for %.0f seconds (sleep or a halted process)."

# ─────────────────────────────────────────── Findings: VPN
VPN_DISCONNECTED = "%s disconnected. Most likely explanation: %s."
VPN_PROTECTION_LOST = ("%s dropped, so traffic is leaving outside the tunnel. Other devices "
                       "on this L2 segment can see it.")
VPN_PROTECTION_LOST_UNKNOWN = "%s dropped. Whether this network can be trusted is undetermined."
VPN_RECONNECTED = "%s reconnected%s."
VPN_STATE_CHANGED = "%s state changed (%s → %s)."
VPN_STATE_UNKNOWN = "%s state could not be read (%s → %s)."
VPN_SINCE = " (down since %s)"

# Most likely explanation for a VPN drop
WHY_USER = "disconnected by the user"
WHY_SLEEP = "sleep"
WHY_MOVED = "network change"
WHY_LINK = "first hop silent — problem between this device and the router"
WHY_TUNNEL = "first hop healthy — tunnel path problem"
WHY_UNKNOWN = "not enough evidence to tell"

DETECTOR_ERROR = "Detector %s stopped with an exception: %s"

# ─────────────────────────────────────────── Investigations
INV_OPENED = "%s triggered investigation %s. Watching until it resolves."
INV_RETUNED = "Investigation %s retuned its criteria: %s"
INV_ABANDONED = "Investigation %s abandoned. The network changed, so the subject is gone."
INV_COOLDOWN = ("Investigation %s just finished. It will not reopen for %d cycles "
                "(the %s signal is still recorded).")
INV_BUDGET_SPENT = "[%s] Watched %d cycles without deciding. Closing with the observations kept."
INV_ERROR = "Investigation %s stopped with an exception: %s"
INV_ABANDON_REASON_NETWORK = "abandoned after a network change"
INV_ABANDON_REASON_NO_PLAYBOOK = "no playbook found"
INV_ABANDON_REASON_ERROR = "error during investigation: %s"
INV_BUDGET_VERDICT = "no conclusion within budget (%d cycles)"

# Playbook: L2 identity
INV_L2_WIDEN = "A MAC change coincided with routing and name resolution changes. Widening scope."
INV_L2_CORROBORATED = ("After the first hop changed identity, %s followed. An access point "
                       "swap alone does not explain this.")
INV_L2_CORROBORATED_VERDICT = "something holding the path changed — possible man in the middle"
INV_L2_FLAPPING = ("Gateway MAC changed %d times across %d distinct values. A normal access "
                   "point swap does not flip back like this.")
INV_L2_FLAPPING_VERDICT = "first hop identity is flapping"
INV_L2_STABLE = ("The new gateway MAC held for %d cycles with nothing following it. "
                 "Likely an access point swap, though an attack is not ruled out.")
INV_L2_STABLE_VERDICT = "settled on a new first hop"

# Playbook: path and name resolution config
INV_PATH_CONTESTED = "Settings keep changing. Treating this as contention, not a single tamper."
INV_PATH_PERSISTED = "The changed routing and name resolution settings held for %d cycles%s."
INV_PATH_CONTESTED_NOTE = " (after flipping several times)"
INV_PATH_VERDICT = "the changed settings took hold"

# Playbook: VPN drops
INV_VPN_WIDEN = "Drops keep repeating. Watching first-hop quality as well."
INV_VPN_REPEATED = "%s dropped %d times. %s."
# Which leg was at fault. Keep the "repeated" framing out of these — reusing
# them in a single-drop conclusion produces "dropped once … repeated drops".
INV_VPN_LEG_TUNNEL = "the first hop was healthy each time — a tunnel-side problem"
INV_VPN_LEG_LINK = "the first hop was unstable at the same time"
INV_VPN_LEG_UNKNOWN = "could not tell which leg"
INV_VPN_VERDICT_TUNNEL = "repeated drops on the tunnel side"
INV_VPN_VERDICT_LINK = "repeated drops alongside an unstable first hop"
INV_VPN_VERDICT_UNKNOWN = "repeated drops — could not tell which leg"

# Short labels kept in the investigation record
INV_NOTE_START = "investigation opened"
INV_NOTE_RETUNE = "criteria changed"
INV_NOTE_MAC_AGAIN = "gateway MAC changed again"
INV_NOTE_CORROBORATED = "other signals appeared alongside"
INV_NOTE_CONFIG_AGAIN = "settings changed again"
INV_NOTE_DROP_AGAIN = "dropped again"
INV_NOTE_RECONNECT = "reconnected"
INV_NOTE_LINK_EVENT = "link event in the same window"
INV_NOTE_SAME_SIGNAL = "same kind of signal again"

# ─────────────────────────────────────────── Report
CONF_CONFIRMED = "confirmed — the observation alone settles it"
CONF_SUSPECT = "suspect  — departs from the baseline; false positives possible"
CONF_POSSIBLE = "possible — structurally possible; no evidence"
REPORT_HEADER = "== %s  %d cycles observed, %d findings"
REPORT_EXPOSURE_TITLE = "-- What is structurally possible on this network (no evidence) --"
REPORT_INVESTIGATION_TITLE = "-- Investigations --"
REPORT_INVESTIGATION_NOTE = "   A meaningful signal is followed until it resolves."
REPORT_SUPPRESSED_TITLE = "-- Suppressed: explained by your own actions or surroundings (%d) --"
REPORT_SUPPRESSED_NOTE = "   Kept, not deleted. Check here if the suppression call was wrong."
REPORT_NO_ACTIVE = "  No active findings."
REPORT_REDACTED = "-- Identifiers masked. %s --"

EXPOSURE_SHARED_PSK = ("Shared password Wi-Fi (%s): anyone who knows the password is on the "
                       "same L2 segment and can forge ARP, DHCP and RA, or decrypt passively.")
EXPOSURE_OPEN = "Unencrypted Wi-Fi: anyone nearby can read the traffic."
EXPOSURE_DNS_PROXY = ("DNS goes through a local proxy. This may be a VPN or filter working "
                      "normally, or interception. This tool cannot tell which is listening.")

# ─────────────────────────────────────────── Live view
WATCH_AGENT_RUNNING = "agent running (pid %s)"
WATCH_AGENT_WAITING = "agent registered, waiting to start"
WATCH_AGENT_NONE = "not registered to run continuously"
WATCH_NO_SAMPLES = "no records yet"
WATCH_STALE = " ← updates stopped"
WATCH_SUMMARY = "%d cycles, last %s"
WATCH_WIRED = "wired"
WATCH_DNS_PROXY = "DNS via local proxy"
WATCH_SECTION_INVESTIGATION = "Investigations"
WATCH_SECTION_FINDINGS = "Recent findings"
WATCH_NO_INVESTIGATION = "no open investigation"
WATCH_NO_FINDINGS = "no findings yet"
WATCH_INV_LINE = "%s  %d cycles  trigger=%s"
WATCH_INV_RETUNED = "criteria changed %d times — last: %s"
WATCH_RULES = "criteria: %s"
WATCH_FOOTER = "Ctrl+C closes this view. Monitoring continues."
WATCH_SUPPRESSED_TAG = "suppressed"

# ─────────────────────────────────────────── Setup wizard
WZ_TITLE = "netmon first-run setup"
WZ_INTRO = ("Press Enter to take the default. The defaults use no sudo, send\n"
            "nothing outside this machine, and do not register anything to run "
            "continuously.")
WZ_PICK = "Choice [%d]: "
WZ_PICK_RANGE = "  Enter a number between 1 and %d."
WZ_YES_NO = "  Answer y or n."
WZ_DEFAULT_MARK = " (default)"

WZ_LANG_Q = "어떤 언어로 표시할까요? / Which language should netmon use?"
WZ_LANG_KO = "한국어"
WZ_LANG_EN = "English"

WZ_INTERVAL_Q = "How often should it measure?"
WZ_INTERVAL_3 = "catches changes quickly, uses a little more battery"
WZ_INTERVAL_5 = "a good fit for most situations"
WZ_INTERVAL_10 = "saves battery, may miss short drops"
WZ_INTERVAL_30 = "very light, coarse quality judgements"

WZ_LOGDIR_Q = "\nWhere should records go?"
WZ_RETENTION_Q = "How many days of records should it keep?"
WZ_RETENTION_7 = "light"
WZ_RETENTION_14 = "default"
WZ_RETENTION_30 = "for looking further back"
WZ_RETENTION_90 = "uses a fair amount of disk"

WZ_LOCATION_HEAD = "[Location] Reads the Wi-Fi name (SSID) and access point id (BSSID)."
WZ_LOCATION_BODY = ("  Used to tell a fake access point using the same name (evil twin)\n"
                    "  apart from normal roaming. Coordinates are never read and the\n"
                    "  values never leave this machine. macOS grants location per app,\n"
                    "  so a small helper app is built.")
WZ_LOCATION_Q = "  Use location permission?"

WZ_VPN_HEAD = "[VPN] VPNs found on this machine: %s"
WZ_VPN_BODY = "  Records connection state and drops. Nothing is sent outside."
WZ_VPN_Q = "  Monitor VPNs?"
WZ_VPN_NONE = "[VPN] No VPN found, skipping."

WZ_EXTERNAL_HEAD = "[Outbound checks] Compares DNS answers against a reference (hijack detection),"
WZ_EXTERNAL_BODY = ("  and watches TLS issuers for fixed hosts plus public IP changes.\n"
                    "  A fixed set of lookup names and this machine's source IP leave the\n"
                    "  machine. Network identifiers such as SSID, BSSID and MAC are not sent.")
WZ_EXTERNAL_Q = "  Enable outbound checks?"

WZ_AGENT_HEAD = "[Always on] Starts at login and restarts if it stops."
WZ_AGENT_BODY = ("  Creates one file in ~/Library/LaunchAgents. No sudo, and\n"
                 "  netmon service uninstall undoes it.")
WZ_AGENT_Q = "  Keep it always on?"

WZ_LINK_HEAD = "[Command] Right now it only runs as ./netmon.sh inside the repository."
WZ_LINK_BODY = ("  From any other directory the shell cannot find the file. A symlink in\n"
                "  a directory on PATH lets you run netmon from anywhere.\n"
                "  No sudo, and netmon link remove undoes it.")
WZ_LINK_Q = "  Make netmon runnable from anywhere?"

WZ_SUMMARY_HEAD = "About to apply:"
WZ_CONFIRM_Q = "\nApply?"
WZ_ROW_LANGUAGE = "language        %s"
WZ_ROW_INTERVAL = "interval        %d seconds"
WZ_ROW_LOGDIR = "records         %s"
WZ_ROW_RETENTION = "retention       %d days"
WZ_ROW_LOCATION = "location        %s  (evil twin detection)"
WZ_ROW_VPN = "VPN monitoring  %s  (%s)"
WZ_ROW_EXTERNAL = "outbound checks %s  (DNS/TLS hijack, public IP)"
WZ_ROW_AGENT = "always on       %s  (start at login)"
WZ_ROW_LINK = "command         %s  (run netmon from anywhere)"
WZ_ON = "on"
WZ_OFF = "off"

# ─────────────────────────────────────────── CLI
CLI_NO_FINDINGS = "  No findings"
CLI_COLLECT_FAILED = "  Collector %s failed: %s"
CLI_RUN_START = "Measuring — every %d seconds, records in %s  (Ctrl+C to stop)"
CLI_RUN_DONE = "Recorded %d cycles → %s"
CLI_RUN_FASTER = "%s  %d investigations open — shortening the interval to %.0f seconds"
CLI_NO_RECORDS = "No records for %s (%s)"
CLI_CAPTURE_START = "Capturing %d cycles to %s (every %d seconds)%s"
CLI_CAPTURE_REDACT = ", identifiers masked"
CLI_CAPTURE_DONE = "Saved → %s"
CLI_REPLAY_START = "Replaying %d cycles — %s"
CLI_REPLAY_DONE = "%d findings"
CLI_DOCTOR_CONFIG = "config   %s"
CLI_DOCTOR_LANG = "language %s (%s)"
CLI_DOCTOR_DATA = "records  %s"
CLI_LANG_CURRENT = "current language  %s (%s)"
CLI_LANG_CONFIG = "config file       %s"
CLI_LANG_ENV = "environment       %s=%s  (overrides the config file)"
CLI_LANG_AVAILABLE = "Available languages:"
CLI_LANG_HOWTO = "To change:  netmon lang ko"
CLI_LANG_FILES = "Message files: netmon/messages/<code>.py"
CLI_LANG_UNKNOWN = "Unknown language code: %s (available: %s)"
CLI_LANG_CHANGED = "Language set to %s (%s) → %s"
CLI_LANG_KEEPS_RECORDS = "Findings already recorded keep their original wording. Records are not rewritten."
CLI_LINK_DONE = "`netmon` now runs from anywhere."
CLI_LINK_PATH = "  link    %s"
CLI_LINK_TARGET = "  target  %s"
CLI_LINK_NOT_ON_PATH = ("This directory is not on PATH. Run the line below, then open a\n"
                        "new terminal and `netmon` will be found:")
CLI_LINK_NONE = "No netmon link on PATH."
CLI_LINK_USE_REPO = "Inside the repository, run it as ./netmon.sh:"
CLI_LINK_HOWTO = "To use it anywhere: netmon link"
CLI_LINK_OTHER_REPO = "  ← points at a different repository"
CLI_LINK_REMOVED = "Removed: %s"
CLI_LINK_SKIPPED = "Skipped (not a symlink): %s"
CLI_LINK_NOTHING = "No link to remove."
CLI_LINK_WHERE = "Linking into: %s (%s)"
CLI_LINK_NO_DIR = "No suitable directory found. Pass one with --dir."
CLI_SETUP_SAVED = "Settings saved → %s"
CLI_SETUP_CANCELLED = "Cancelled. Nothing was changed."
CLI_SETUP_DONE = "Setup complete. Check it with:  %s doctor"
CLI_SETUP_NEXT_RUN = "Start measuring:              %s run"
CLI_SETUP_BUILD_HELPER = "Building the location helper..."
CLI_SETUP_NO_LOCATION = "Location permission was not granted. Everything else still works."
CLI_AGENT_INTRO = ("Starts at login and restarts if it stops.\n"
                   "Creates one file in ~/Library/LaunchAgents. No sudo required.")
CLI_AGENT_DONE = "Registered to run continuously."
CLI_AGENT_FAILED = "Registration failed: %s"
CLI_AGENT_REMOVED = "Removed."
CLI_AGENT_NOT_INSTALLED = "It was not registered."
CLI_AGENT_RECORDS_KEPT = "Records are still in %s."

# ─────────────────────────────────────────── Found by reading real logs
ARP_REPLY_SPIKE_RATE = "ARP replies arriving at %.1f per second (usually %.1f)."
LATENCY_SPIKE_SUSTAINED = "Gateway round-trip time rose to %.0fms (average %.0fms, %d cycles running)."
INV_L2_NO_CHANGE = "First hop identity held unchanged for %d cycles. No sign of spoofing."
INV_L2_NO_CHANGE_VERDICT = "first hop identity unchanged"

# ─────────────────────────────────────────── Found in the WARP drop logs
INV_VPN_SETTLED = "%s dropped %d times, then stayed steady for %d cycles. %s."
INV_VPN_VERDICT_SETTLED = "recovered and settled after %d drop(s)"

# ─────────────────────────────────────────── Ambiguous network identity
EXPOSURE_IDENTITY_AMBIGUOUS = (
    "No location permission, so the SSID cannot be read. Two different places using the "
    "same private range (192.168.0.0/24, say) look identical, which makes a first-hop "
    "change after moving hard to tell apart from an attack.")

# ─────────────────────────────────────────── Incomplete observation
LINK_ABSENT = "No primary interface, so this cycle is not judged. The link is down."
WHY_LINK_GONE = "the link itself went away"

# ─────────────────────────────────────────── Day boundary
DAY_IS_UTC = "Dates are in UTC (local time %s)."
WHY_WOKE = "waking from sleep"
WHY_LINK_BACK = "the link had just come back"

# ─────────────────────────────────────────── Exposure by encryption type
EXPOSURE_SHARED_SAE = ("WPA3-SAE Wi-Fi (%s): anyone who knows the password can join the same "
                       "L2 segment and forge ARP, DHCP and RA. Keys differ per session, "
                       "though, so knowing the password does not decrypt others' traffic.")
VPN_PROTECTION_LOST_SAE = ("%s dropped, so traffic is leaving outside the tunnel. WPA3-SAE means "
                           "it is not readable passively, but a device that joined the segment "
                           "could still intercept the path and see it.")
