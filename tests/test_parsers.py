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


if __name__ == "__main__":
    unittest.main()
