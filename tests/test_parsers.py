"""파서 — 실제 macOS 출력 형식을 합성값으로 재현해서 검증한다.

형식은 macOS 26.6.2 에서 확인했다. 열 수와 구분자가 버전마다 다를 수 있어
파서는 열 위치보다 토큰 의미에 기대도록 썼고, 그것을 여기서 고정한다.
"""
from __future__ import annotations

import unittest

from netmon.collect import arp, dhcp, dns, iface, link, route, wifi

ARP_OUT = """Neighbor                Linklayer Address Expire(O) Expire(I)          Netif Refs Prbs RSSI    LQM     NPM
192.0.2.254             (incomplete)      (none)    (none)         en0
192.0.2.1               00:00:5e:00:53:01 2m54s     1m37s          en0    1 none unknown unknown unknown
192.0.2.77              00:00:5e:00:53:07 19m2s     8m1s           en0    0 none unknown unknown unknown
"""

ARP_STATS = """arp:
\t5646 broadast ARP requests sent
\t14982 ARP replies sent
\t3180838 ARP requests received
\t309522 ARP replies received
\t0 Duplicate IP seen
"""

GETPACKET = """op = BOOTREPLY
htype = 1
hlen = 6
yiaddr = 192.0.2.50
chaddr = 00:00:5e:00:53:0a
options:
Options count is 7
dhcp_message_type (uint8): ACK 0x5
server_identifier (ip): 192.0.2.1
lease_time (uint32): 0x1c20
subnet_mask (ip): 255.255.255.0
router (ip_mult): {192.0.2.1}
domain_name_server (ip_mult): {192.0.2.53, 198.51.100.53}
end (none):
"""

SCUTIL_DNS = """DNS configuration

resolver #1
  nameserver[0] : 192.0.2.53
  nameserver[1] : 198.51.100.53
  flags    : Request A records
  reach    : 0x00030002 (Reachable)

resolver #2
  domain   : local
  options  : mdns
  timeout  : 5
"""

SCUTIL_PROXY_OFF = """<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
  }
  FTPPassive : 1
}
"""

SCUTIL_PROXY_WPAD = """<dictionary> {
  FTPPassive : 1
  ProxyAutoDiscoveryEnable : 1
}
"""

NETSTAT_V4 = """Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.0.2.1          UGScg                 en0
default            link#26            UCSIg               utun6
192.0.2/24         link#12            UCS                   en0
"""

NDP_OUT = """2001:db8::1 if=en0, flags=OR, pref=medium, expire=29m
fe80::%utun0 if=utun0, flags=IST, pref=medium, expire=Never
"""

HW_PORTS = """Hardware Port: Wi-Fi
Device: en0
Ethernet Address: 00:00:5e:00:53:0a

Hardware Port: Thunderbolt Bridge
Device: bridge0
Ethernet Address: 00:00:5e:00:53:0b
"""

IFCONFIG = """en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 00:00:5e:00:53:0a
\tinet6 2001:db8::50%en0 prefixlen 64 secured scopeid 0xc
\tinet 192.0.2.50 netmask 0xffffff00 broadcast 192.0.2.255
\tmedia: autoselect
\tstatus: active
"""

GETSUMMARY_REDACTED = """ServiceID : 11111111-2222-3333-4444-555555555555
  SSID : <redacted>
  BSSID : <redacted>
  Security : WPA2
  LinkStatusActive : TRUE
  LeaseStartTime : 0x600000
  RouterARPVerified : TRUE
"""

GETSUMMARY_GRANTED = GETSUMMARY_REDACTED.replace("SSID : <redacted>", "SSID : ExampleNet") \
    .replace("BSSID : <redacted>", "BSSID : 00:00:5e:00:53:aa")

PING_OK = """PING 192.0.2.1 (192.0.2.1): 56 data bytes
64 bytes from 192.0.2.1: icmp_seq=0 ttl=64 time=3.51 ms
64 bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=4.02 ms

--- 192.0.2.1 ping statistics ---
2 packets transmitted, 2 packets received, 0.0% packet loss
"""

PING_FAIL = """PING 192.0.2.1 (192.0.2.1): 56 data bytes
Request timeout for icmp_seq 0

--- 192.0.2.1 ping statistics ---
2 packets transmitted, 0 packets received, 100.0% packet loss
"""


class TestArp(unittest.TestCase):
    def test_table_handles_incomplete_rows(self):
        rows = arp.parse_arp_table(ARP_OUT)
        self.assertEqual(len(rows), 3)
        self.assertIsNone(rows[0]["mac"], "(incomplete) 는 MAC 없음으로 읽어야 한다")
        self.assertEqual(rows[1]["mac"], "00:00:5e:00:53:01")
        self.assertEqual(rows[1]["iface"], "en0")

    def test_lookup(self):
        rows = arp.parse_arp_table(ARP_OUT)
        self.assertEqual(arp.lookup(rows, "192.0.2.1", "en0"), "00:00:5e:00:53:01")
        self.assertIsNone(arp.lookup(rows, "192.0.2.254", "en0"))

    def test_stats_tolerate_apple_typo(self):
        """macOS 는 'broadast' 로 오타를 낸다. 정확한 문자열 비교를 쓰면 깨진다."""
        stats = arp.parse_arp_stats(ARP_STATS)
        self.assertEqual(arp.stat_like(stats, "duplicate", "ip"), 0)
        self.assertEqual(arp.stat_like(stats, "arp replies received"), 309522)


class TestDhcp(unittest.TestCase):
    def test_getpacket_options(self):
        p = dhcp.parse_getpacket(GETPACKET)
        self.assertEqual(p["options"]["server_identifier"], "192.0.2.1")
        self.assertEqual(p["options"]["router"], ["192.0.2.1"])
        self.assertEqual(p["options"]["domain_name_server"],
                         ["192.0.2.53", "198.51.100.53"])
        self.assertEqual(p["header"]["yiaddr"], "192.0.2.50")

    def test_getsummary_keys(self):
        s = dhcp.parse_getsummary(GETSUMMARY_REDACTED)
        self.assertEqual(s["Security"], "WPA2")
        self.assertEqual(s["RouterARPVerified"], "TRUE")


class TestDns(unittest.TestCase):
    def test_primary_resolvers_skip_mdns(self):
        parsed = dns.parse_scutil_dns(SCUTIL_DNS)
        self.assertEqual(len(parsed["resolvers"]), 2)
        self.assertEqual(dns.primary_resolvers(parsed),
                         ["192.0.2.53", "198.51.100.53"])

    def test_proxy_flat_keys_only(self):
        off = dns.parse_scutil_proxy(SCUTIL_PROXY_OFF)
        self.assertNotIn("0", off, "중첩 배열의 항목이 최상위로 올라오면 안 된다")
        self.assertEqual(off.get("FTPPassive"), "1")
        wpad = dns.parse_scutil_proxy(SCUTIL_PROXY_WPAD)
        self.assertEqual(wpad.get("ProxyAutoDiscoveryEnable"), "1")

    def test_loopback(self):
        self.assertTrue(dns.is_loopback("127.0.2.2"))
        self.assertFalse(dns.is_loopback("192.0.2.53"))


class TestRoute(unittest.TestCase):
    def test_default_routes_only(self):
        rows = route.parse_netstat_routes(NETSTAT_V4)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["iface"], "en0")
        self.assertEqual(rows[1]["iface"], "utun6")
        self.assertEqual(rows[1]["gateway"], "link#26")

    def test_ndp_routers(self):
        rows = route.parse_ndp_routers(NDP_OUT)
        self.assertEqual(rows[0]["addr"], "2001:db8::1")
        self.assertEqual(rows[0]["if"], "en0")


class TestIface(unittest.TestCase):
    def test_hardware_ports(self):
        ports = iface.parse_hardware_ports(HW_PORTS)
        self.assertEqual(ports[0], {"port": "Wi-Fi", "dev": "en0", "kind": "wifi"})
        self.assertEqual(ports[1]["kind"], "ethernet")

    def test_ifconfig(self):
        st = iface.parse_ifconfig(IFCONFIG)
        self.assertEqual(st["status"], "active")
        self.assertEqual(st["ether"], "00:00:5e:00:53:0a")
        self.assertEqual(st["inet"][0]["addr"], "192.0.2.50")
        self.assertEqual(st["inet6"][0]["addr"], "2001:db8::50")

    def test_tunnel_detection(self):
        self.assertTrue(iface.is_tunnel("utun6"))
        self.assertFalse(iface.is_tunnel("en0"))

    def test_primary_falls_back_to_physical_when_default_is_tunnel(self):
        """VPN 이 기본 경로를 쥐고 있어도 물리 인터페이스를 찾아야 한다."""
        ports = iface.parse_hardware_ports(HW_PORTS)
        state = {"en0": iface.parse_ifconfig(IFCONFIG)}
        self.assertEqual(
            iface.choose_primary(ports, ["en0", "bridge0"], state, "utun6"), "en0")
        self.assertEqual(
            iface.choose_primary(ports, ["en0"], state, "en0"), "en0")


class TestWifi(unittest.TestCase):
    def test_redacted_means_no_location_permission(self):
        p = wifi.parse_wifi_summary(GETSUMMARY_REDACTED)
        self.assertEqual(wifi.location_state(p), "denied")
        self.assertEqual(p["security"], "WPA2",
                         "암호화 방식은 권한 없이도 읽힌다")

    def test_granted(self):
        p = wifi.parse_wifi_summary(GETSUMMARY_GRANTED)
        self.assertEqual(wifi.location_state(p), "granted")
        self.assertEqual(p["ssid"], "ExampleNet")


class TestLink(unittest.TestCase):
    def test_ping_ok(self):
        r = link.parse_ping(PING_OK)
        self.assertEqual(r["replies"], 2)
        self.assertEqual(r["rtt_ms"], 3.76)  # (3.51+4.02)/2 = 3.765
        self.assertEqual(r["loss_pct"], 0.0)

    def test_ping_fail(self):
        r = link.parse_ping(PING_FAIL)
        self.assertEqual(r["replies"], 0)
        self.assertIsNone(r["rtt_ms"])
        self.assertEqual(r["loss_pct"], 100.0)




class TestCandidateStatesWhenThereIsNoPrimary(unittest.TestCase):
    """2026-09-20 맥북: 주 인터페이스 없는 주기 56건에서 후보 상태가 기록되지
    않아, 무선이 끊겨 있었는지 붙어 있었는데 IPv4 만 없었는지 가릴 수 없었다."""

    PORTS = [{"dev": "en0", "kind": "wifi"}, {"dev": "en1", "kind": "ethernet"},
             {"dev": "utun4", "kind": "tunnel"}]

    def test_it_keeps_status_for_each_physical_candidate(self):
        st = {"en0": {"status": "inactive", "flags_up": True, "inet": [], "inet6": []},
              "en1": {"status": "active", "flags_up": True,
                      "inet": [{"addr": "192.0.2.10"}], "inet6": []}}
        got = iface.candidate_states(self.PORTS, st)
        self.assertEqual([c["kind"] for c in got], ["wifi", "ethernet"])
        self.assertEqual(got[0]["status"], "inactive")
        self.assertFalse(got[0]["has_inet"])
        self.assertTrue(got[1]["has_inet"])

    def test_it_tells_a_dead_radio_from_one_that_is_up_without_an_address(self):
        dead = iface.candidate_states(
            self.PORTS[:1], {"en0": {"status": "inactive", "flags_up": False,
                                     "inet": [], "inet6": []}})[0]
        up_no_ip = iface.candidate_states(
            self.PORTS[:1], {"en0": {"status": "active", "flags_up": True,
                                     "inet": [], "inet6": []}})[0]
        self.assertNotEqual((dead["status"], dead["flags_up"]),
                            (up_no_ip["status"], up_no_ip["flags_up"]))

    def test_it_records_no_addresses(self):
        st = {"en0": {"status": "active", "flags_up": True,
                      "inet": [{"addr": "192.0.2.10"}],
                      "inet6": [{"addr": "2001:db8::1"}], "ether": "00:00:5e:00:53:01"}}
        got = iface.candidate_states(self.PORTS[:1], st)[0]
        self.assertNotIn("192.0.2.10", repr(got))
        self.assertNotIn("2001:db8::1", repr(got))
        self.assertNotIn("00:00:5e:00:53:01", repr(got))


class TestCollectWiresCandidatesToTheMissingPrimary(unittest.TestCase):
    """후보 상태는 **주 인터페이스가 없을 때만** 실린다. 배선 자체를 검사한다."""

    WIFI_DOWN = ("en0: flags=8822<BROADCAST,SMART,SIMPLEX,MULTICAST> mtu 1500\n"
                 "\tether 00:00:5e:00:53:0a\n\tstatus: inactive\n")
    WIFI_UP = ("en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
               "\tether 00:00:5e:00:53:0a\n\tinet 192.0.2.50 netmask 0xffffff00\n"
               "\tstatus: active\n")

    def _collect(self, ifconfig_out, route_out):
        from netmon.util import CmdResult

        def fake_run(argv, timeout=None, stdin=""):
            cmd = " ".join(argv)
            if "listallhardwareports" in cmd:
                return CmdResult(argv, 0, HW_PORTS, "")
            if "listnetworkserviceorder" in cmd:
                return CmdResult(argv, 0, "", "")
            if argv[0] == "ifconfig":
                return CmdResult(argv, 0, ifconfig_out if argv[1] == "en0" else "", "")
            if argv[0] == "route":
                return CmdResult(argv, 0, route_out, "")
            return CmdResult(argv, 0, "", "")

        orig = iface.run
        iface.run = fake_run
        try:
            return iface.collect()
        finally:
            iface.run = orig

    def test_a_missing_primary_carries_candidate_states(self):
        got = self._collect(self.WIFI_DOWN, "")
        self.assertIsNone(got["primary"])
        self.assertEqual([c["kind"] for c in got["candidates"]], ["wifi"])
        self.assertEqual(got["candidates"][0]["status"], "inactive")
        self.assertFalse(got["candidates"][0]["flags_up"])

    def test_a_present_primary_carries_none(self):
        route = "   route to: default\n destination: default\n    gateway: 192.0.2.1\n  interface: en0\n"
        got = self._collect(self.WIFI_UP, route)
        self.assertEqual(got["primary"], "en0")
        self.assertIsNone(got["candidates"])


class TestWifiIsReadEvenWithoutAPrimary(unittest.TestCase):
    """주 인터페이스가 없는 주기가 무선 상태를 가장 알고 싶은 순간이다.
    예전에는 primary_kind 가 unknown 이라 수집을 통째로 건너뛰었다."""

    SUMMARY = "  Security : WPA2_PSK\n  LinkStatusActive : TRUE\n"

    def _collect(self, ctx):
        from netmon.util import CmdResult
        calls = []

        def fake_run(argv, timeout=None, stdin=""):
            calls.append(argv)
            return CmdResult(argv, 0, self.SUMMARY, "")

        orig = wifi.run
        wifi.run = fake_run
        try:
            return wifi.collect(ctx), calls
        finally:
            wifi.run = orig

    def test_no_primary_reads_the_radio_directly(self):
        got, calls = self._collect({"primary": None, "primary_kind": "unknown",
                                    "wifi_fallback_dev": "en0"})
        self.assertTrue(got["applicable"])
        self.assertIs(got["is_primary"], False)
        self.assertEqual(got["security"], "WPA2_PSK")
        self.assertIn("en0", calls[0])

    def test_a_wired_primary_is_left_alone(self):
        got, calls = self._collect({"primary": "en1", "primary_kind": "ethernet",
                                    "wifi_fallback_dev": "en0"})
        self.assertFalse(got["applicable"])
        self.assertEqual(calls, [])

    def test_no_radio_at_all_says_so(self):
        got, calls = self._collect({"primary": None, "primary_kind": "unknown",
                                    "wifi_fallback_dev": None})
        self.assertFalse(got["applicable"])
        self.assertEqual(calls, [])

    def test_no_primary_never_asks_the_location_helper(self):
        """헬퍼 값은 최대 15초 캐시라, 끊기기 직전 값이 이번 주기 관측처럼
        기록된다. 이 주기에 실제로 읽은 값만 남긴다."""
        from netmon.collect import wifi as wifimod
        called = []

        def fake_helper(*a, **kw):
            called.append(kw)
            return {"ssid": "ExampleNet", "bssid": None, "rssi": -40}

        orig = wifimod.wifi_helper.wifi
        wifimod.wifi_helper.wifi = fake_helper
        try:
            got, _calls = self._collect({"primary": None, "primary_kind": "unknown",
                                         "wifi_fallback_dev": "en0",
                                         "allow_location": True,
                                         "wifi_force_refresh": True})
        finally:
            wifimod.wifi_helper.wifi = orig
        self.assertEqual(called, [])
        self.assertIsNone(got["ssid"])
        self.assertTrue(got["identity_withheld"])

    def test_a_primary_cycle_still_asks_the_helper(self):
        from netmon.collect import wifi as wifimod
        called = []

        def fake_helper(*a, **kw):
            called.append(kw)
            return {"ssid": "ExampleNet", "bssid": None, "rssi": -40}

        orig = wifimod.wifi_helper.wifi
        wifimod.wifi_helper.wifi = fake_helper
        try:
            got, _calls = self._collect({"primary": "en0", "primary_kind": "wifi",
                                         "allow_location": True,
                                         "wifi_force_refresh": True})
        finally:
            wifimod.wifi_helper.wifi = orig
        self.assertEqual(len(called), 1)
        self.assertTrue(called[0]["force"])
        self.assertEqual(got["location"], "granted-via-helper")

    def test_a_wifi_primary_is_marked_as_primary(self):
        got, _calls = self._collect({"primary": "en0", "primary_kind": "wifi"})
        self.assertIs(got["is_primary"], True)


if __name__ == "__main__":
    unittest.main()
