"""탐지 항목별 판정 — 장애·공격 상황을 입력 주입으로 재현한다.

실제 네트워크에서 공격을 재현하지 않는다. 여기 있는 것은 전부 합성 관측이다.
"""
from __future__ import annotations

import unittest

from netmon.detect import Context, attributions_for, network_key, run_all
from tests.helpers import (BSSID, BSSID_ALT, DNS1, DNS2, GW, GW_MAC,
                           GW_MAC_ALT, SSID, by_kind, kinds, obs)

ALL_ON = {"detect.l2": True, "detect.dhcp": True, "detect.dns": True,
          "detect.route": True, "detect.wifi": True, "detect.quality": True,
          "detect.evil_twin": True}


def judge(prev, cur, state=None, features=None, elapsed=5.0):
    attrs = attributions_for(prev, cur, elapsed, 5.0)
    ctx = Context(elapsed=elapsed, interval=5.0, features=features or ALL_ON,
                  state=state or {}, attributions=attrs, network=network_key(cur))
    return run_all(prev, cur, ctx)


class TestRogueDhcp(unittest.TestCase):
    def test_dhcp_server_change_on_same_network(self):
        prev = obs()
        cur = obs(dhcp_server="192.0.2.99")
        f = by_kind(judge(prev, cur), "DHCP_SERVER_CHANGED")
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.confidence, "confirmed")

    def test_dhcp_dns_option_change(self):
        prev = obs(dns=(DNS1,))
        cur = obs(dns=("192.0.2.66",))
        f = by_kind(judge(prev, cur), "DHCP_DNS_CHANGED")
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, "high")


class TestDnsAndProxy(unittest.TestCase):
    def test_resolver_change(self):
        f = by_kind(judge(obs(resolvers=(DNS1,)), obs(resolvers=("192.0.2.66",))),
                    "RESOLVER_CHANGED")
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, "high")

    def test_wpad_turned_on_is_high(self):
        prev = obs(proxy={})
        cur = obs(proxy={"ProxyAutoDiscoveryEnable": "1"})
        f = by_kind(judge(prev, cur), "PROXY_ENABLED")
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, "high")

    def test_loopback_resolver_is_not_itself_an_alarm(self):
        """VPN·DNS 필터를 쓰면 루프백 리졸버가 정상이다. 상태가 같으면 조용해야 한다."""
        prev = obs(resolvers=("127.0.2.2",), via_loopback=True)
        cur = obs(resolvers=("127.0.2.2",), via_loopback=True)
        self.assertEqual(kinds(judge(prev, cur)), [])

    def test_loopback_state_change_is_suspect_not_confirmed(self):
        prev = obs(resolvers=(DNS1,), via_loopback=False)
        cur = obs(resolvers=("127.0.2.2",), via_loopback=True)
        f = by_kind(judge(prev, cur), "DNS_LOCAL_PROXY_CHANGED")
        self.assertIsNotNone(f)
        self.assertEqual(f.confidence, "suspect",
                         "VPN 을 켜는 정상 동작과 구분할 수 없으므로 확정이 아니다")


class TestIpv6Ra(unittest.TestCase):
    def test_ipv6_default_route_appearing_on_physical_iface(self):
        prev = obs(default6=())
        cur = obs(default6=(("2001:db8::1", "en0"),))
        f = by_kind(judge(prev, cur), "IPV6_DEFAULT_ROUTE_APPEARED")
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, "high")

    def test_ipv6_route_via_tunnel_is_not_flagged(self):
        """VPN 을 켜면 터널에 IPv6 기본 경로가 생긴다. 공격이 아니다."""
        prev = obs(default6=())
        cur = obs(default6=(("2001:db8::9", "utun4"),))
        self.assertIsNone(by_kind(judge(prev, cur), "IPV6_DEFAULT_ROUTE_APPEARED"))


class TestWifiSecurity(unittest.TestCase):
    def test_downgrade_is_high(self):
        f = by_kind(judge(obs(security="WPA3"), obs(security="WPA2")),
                    "WIFI_SECURITY_DOWNGRADE")
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, "high")

    def test_open_network_downgrade(self):
        f = by_kind(judge(obs(security="WPA2"), obs(security="None")),
                    "WIFI_SECURITY_DOWNGRADE")
        self.assertIsNotNone(f)

    def test_upgrade_is_not_a_downgrade(self):
        f = by_kind(judge(obs(security="WPA2"), obs(security="WPA3")),
                    "WIFI_SECURITY_CHANGED")
        self.assertIsNotNone(f)
        self.assertNotEqual(f.kind, "WIFI_SECURITY_DOWNGRADE")

    def test_unknown_security_string_does_not_claim_downgrade(self):
        """모르는 문자열을 약해졌다고 단정하지 않는다."""
        f = by_kind(judge(obs(security="WPA2"), obs(security="ZZZ-Unknown")),
                    "WIFI_SECURITY_CHANGED")
        self.assertIsNotNone(f)
        self.assertEqual(f.kind, "WIFI_SECURITY_CHANGED")


class TestEvilTwin(unittest.TestCase):
    def test_roam_with_same_gateway_is_just_roaming(self):
        prev = obs(ssid=SSID, bssid=BSSID, gw_mac=GW_MAC)
        cur = obs(ssid=SSID, bssid=BSSID_ALT, gw_mac=GW_MAC)
        f = by_kind(judge(prev, cur), "WIFI_ROAM")
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, "info")
        self.assertIsNone(by_kind(judge(prev, cur), "EVIL_TWIN_CANDIDATE"))

    def test_roam_with_gateway_mac_change_is_evil_twin_candidate(self):
        """같은 SSID 인데 AP 와 게이트웨이가 함께 바뀌면 의심한다."""
        prev = obs(ssid=SSID, bssid=BSSID, gw_mac=GW_MAC)
        cur = obs(ssid=SSID, bssid=BSSID_ALT, gw_mac=GW_MAC_ALT)
        findings = judge(prev, cur)
        f = by_kind(findings, "EVIL_TWIN_CANDIDATE")
        self.assertIsNotNone(f)
        self.assertEqual(f.confidence, "suspect", "정상 로밍과 완전히 구분할 수는 없다")
        self.assertEqual(f.severity, "high")
        self.assertIn("GW_MAC_CHANGED", kinds(findings),
                      "MAC 변경 판정도 따로 남아야 한다")

    def test_bssid_detection_off_without_consent(self):
        """동의가 없으면 수집기가 BSSID 를 담지 않으므로 판정도 나오지 않는다."""
        prev = obs(ssid=None, bssid=None, gw_mac=GW_MAC)
        cur = obs(ssid=None, bssid=None, gw_mac=GW_MAC)
        self.assertIsNone(by_kind(judge(prev, cur), "WIFI_ROAM"))


class TestArpAnomalies(unittest.TestCase):
    def test_duplicate_ip(self):
        f = by_kind(judge(obs(duplicate_ip=0), obs(duplicate_ip=3)), "DUPLICATE_IP")
        self.assertIsNotNone(f)
        self.assertEqual(f.confidence, "confirmed")

    def test_arp_reply_spike_needs_baseline(self):
        prev = obs(arp_replies=1000)
        cur = obs(arp_replies=1000 + 900)
        self.assertIsNone(by_kind(judge(prev, cur, state={}), "ARP_REPLY_SPIKE"),
                          "기준선이 없으면 급변을 주장하지 않는다")
        f = by_kind(judge(prev, cur, state={"arp_reply_rate": 5.0}), "ARP_REPLY_SPIKE")
        self.assertIsNotNone(f)
        self.assertEqual(f.confidence, "suspect")

    def test_small_increase_is_not_a_spike(self):
        prev = obs(arp_replies=1000)
        cur = obs(arp_replies=1010)
        self.assertIsNone(
            by_kind(judge(prev, cur, state={"arp_reply_rate": 5.0}), "ARP_REPLY_SPIKE"))


class TestDetectorIsolation(unittest.TestCase):
    def test_one_broken_detector_does_not_stop_the_rest(self):
        from netmon.detect import REGISTRY

        class Boom:
            FEATURE = "detect.l2"

            @staticmethod
            def detect(prev, cur, ctx):
                raise RuntimeError("의도한 실패")

        original = list(REGISTRY)
        try:
            REGISTRY[:] = [Boom] + [m for m in original if m.FEATURE != "detect.l2"]
            findings = judge(obs(), obs(dhcp_server="192.0.2.99"))
            self.assertIn("DETECTOR_ERROR", kinds(findings))
            self.assertIn("DHCP_SERVER_CHANGED", kinds(findings))
        finally:
            REGISTRY[:] = original


if __name__ == "__main__":
    unittest.main()
