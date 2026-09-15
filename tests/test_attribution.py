"""억제 규칙 — 이 도구에서 가장 틀리기 쉬운 부분.

원래 스크립트는 끊김 원인을 하나만 골랐고 순서가
SLEEP > NETWORK_CHANGE > ARP_ANOMALY 였다. 그래서 네트워크가 바뀌는 동시에
게이트웨이 MAC 이 바뀌면 — evil twin 으로 유인당하는 바로 그 순간 —
ARP 이상이 기록되지 않았다. 이 파일은 그 회귀를 막는다.
"""
from __future__ import annotations

import unittest

from netmon.detect import Context, attributions_for, network_key, run_all
from tests.helpers import (DHCP_SRV, DHCP_SRV2, GW, GW2, GW2_MAC, GW_MAC,
                           GW_MAC_ALT, by_kind, kinds, obs)

FEATURES = {"detect.l2": True, "detect.dhcp": True, "detect.dns": True,
            "detect.route": True, "detect.wifi": True, "detect.quality": True}


def judge(prev, cur, elapsed=5.0, interval=5.0, state=None, features=None):
    attrs = attributions_for(prev, cur, elapsed, interval)
    ctx = Context(elapsed=elapsed, interval=interval,
                  features=features or FEATURES, state=state or {},
                  attributions=attrs, network=network_key(cur))
    return run_all(prev, cur, ctx), attrs


class TestNetworkIdentity(unittest.TestCase):
    def test_gateway_mac_is_not_part_of_identity(self):
        """MAC 은 네트워크 정체성에 들어가면 안 된다.

        들어가면 MAC 이 바뀔 때마다 '다른 네트워크로 옮겼다'가 되어
        스스로 경보를 지운다.
        """
        a = obs(gw_mac=GW_MAC)
        b = obs(gw_mac=GW_MAC_ALT)
        self.assertEqual(network_key(a), network_key(b))

    def test_moving_to_another_network_changes_identity(self):
        a = obs(gateway=GW, dhcp_server=DHCP_SRV, my_ip="192.0.2.50")
        b = obs(gateway=GW2, dhcp_server=DHCP_SRV2, gw_mac=GW2_MAC,
                my_ip="198.51.100.50")
        self.assertNotEqual(network_key(a), network_key(b))


class TestMacChangeNotMasked(unittest.TestCase):
    def test_mac_change_on_same_network_is_high(self):
        prev = obs(ts="2026-01-01T00:00:00Z", gw_mac=GW_MAC)
        cur = obs(ts="2026-01-01T00:00:05Z", gw_mac=GW_MAC_ALT)
        findings, attrs = judge(prev, cur)
        f = by_kind(findings, "GW_MAC_CHANGED")
        self.assertIsNotNone(f, "같은 네트워크에서 MAC 이 바뀌면 반드시 판정이 나와야 한다")
        self.assertEqual(f.severity, "high")
        self.assertIsNone(f.attribution)
        self.assertEqual(attrs, [])

    def test_mac_change_during_network_move_is_recorded_but_attributed(self):
        """네트워크 이동으로 설명돼도 판정은 남는다. 심각도만 내려간다."""
        prev = obs(ts="2026-01-01T00:00:00Z", gateway=GW, gw_mac=GW_MAC,
                   dhcp_server=DHCP_SRV, my_ip="192.0.2.50")
        cur = obs(ts="2026-01-01T00:00:05Z", gateway=GW2, gw_mac=GW2_MAC,
                  dhcp_server=DHCP_SRV2, routers=(GW2,), my_ip="198.51.100.50")
        findings, attrs = judge(prev, cur)
        self.assertIn("network_change", attrs)
        f = by_kind(findings, "GW_MAC_CHANGED")
        self.assertIsNotNone(f, "억제는 판정을 지우는 것이 아니다")
        self.assertEqual(f.attribution, "network_change")
        self.assertEqual(f.severity, "low")

    def test_sleep_does_not_suppress_security_findings(self):
        """자는 동안 MAC 이 바뀌는 것이야말로 확인해야 할 일이다.

        원래 스크립트는 SLEEP 을 가장 우선해서 이 경우를 통째로 삼켰다.
        """
        prev = obs(ts="2026-01-01T00:00:00Z", gw_mac=GW_MAC)
        cur = obs(ts="2026-01-01T02:00:00Z", gw_mac=GW_MAC_ALT)
        findings, attrs = judge(prev, cur, elapsed=7200.0)
        self.assertIn("sleep", attrs)
        f = by_kind(findings, "GW_MAC_CHANGED")
        self.assertIsNotNone(f)
        self.assertIsNone(f.attribution, "잠자기는 보안 판정을 설명하지 못한다")
        self.assertEqual(f.severity, "high")

    def test_sleep_does_suppress_quality_findings(self):
        prev = obs(ts="2026-01-01T00:00:00Z")
        cur = obs(ts="2026-01-01T02:00:00Z", lease_start="2026-01-01 02:00:00")
        findings, attrs = judge(prev, cur, elapsed=7200.0)
        f = by_kind(findings, "DHCP_LEASE_RENEWED")
        self.assertIsNotNone(f)
        self.assertEqual(f.attribution, "sleep")


class TestAxesAreIndependent(unittest.TestCase):
    def test_one_cycle_can_produce_both_axes(self):
        """품질 사건이 보안 사건을 가리지 않는다. 둘 다 나와야 한다."""
        prev = obs(ts="2026-01-01T00:00:00Z", gw_mac=GW_MAC,
                   lease_start="2026-01-01 00:00:00")
        cur = obs(ts="2026-01-01T00:00:05Z", gw_mac=GW_MAC_ALT,
                  lease_start="2026-01-01 00:00:04")
        findings, _ = judge(prev, cur)
        axes = {f.axis for f in findings}
        self.assertIn("security", axes)
        self.assertIn("quality", axes)
        self.assertIn("GW_MAC_CHANGED", kinds(findings))
        self.assertIn("DHCP_LEASE_RENEWED", kinds(findings))


class TestFirstSample(unittest.TestCase):
    def test_first_sample_produces_no_change_findings(self):
        findings, attrs = judge(None, obs())
        self.assertEqual(attrs, ["first_sample"])
        self.assertEqual([f for f in findings if f.axis == "security"], [])


if __name__ == "__main__":
    unittest.main()
