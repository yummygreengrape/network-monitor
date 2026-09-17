"""링크가 끊겼다 붙은 사실을 "설명" 이 아니라 "안정화 중" 으로만 쓴다.

2026-09-17 01:18:55 에 실제로 난 일. Wi-Fi 링크가 11초 끊긴 사이 WARP 가
내려갔다 올라왔고, 링크가 돌아온 주기에 리졸버가 로컬 프록시에서 DHCP 가
알린 값으로 한 번 튀었다. 같은 전환 30건 중 28건은 vpn_change 로 귀속돼
low 였는데, 이 2건만 귀속 없이 high 로 올라갔다.

원인은 link_restart 가 `not ssid_known(cur)` 조건에 걸려 붙지 않은 것.
그 조건은 정체성 판정을 지키려고 있는 것이므로 그대로 두고, 안정화 창만
링크 단절 사실로 따로 연다.
"""
from __future__ import annotations

import unittest

from netmon import baseline
from netmon.detect import Context, attributions_for, network_key, run_all
from tests.helpers import GW_MAC, GW_MAC_ALT, SSID, by_kind, obs, vpn_state

ON = {k: True for k in ("detect.l2", "detect.dhcp", "detect.dns", "detect.route",
                        "detect.wifi", "detect.quality", "detect.vpn",
                        "detect.evil_twin")}


def _ctx(attrs, state, elapsed=5.0, cur=None):
    return Context(elapsed=elapsed, interval=5.0, features=ON, state=state,
                   attributions=attrs, network=network_key(cur) if cur else "")


class TestLinkGapOpensTheWindowWithoutExcusing(unittest.TestCase):
    def test_a_known_ssid_still_does_not_get_link_restart_as_an_excuse(self):
        # 이 가드가 evil twin 을 지킨다. 링크 한 번 끊고 들어오면 끝나면 안 된다.
        before = obs(ssid=SSID, bssid="00:00:5e:00:53:aa")
        back = obs(ssid=SSID, bssid="00:00:5e:00:53:aa", gw_mac=GW_MAC_ALT)
        attrs = attributions_for(before, back, 5.0, 5.0, anchor=before, link_gap=True)
        self.assertNotIn("link_restart", attrs)

    def test_the_gateway_mac_change_is_still_judged_after_a_link_gap(self):
        before = obs(ssid=SSID, bssid="00:00:5e:00:53:aa")
        back = obs(ssid=SSID, bssid="00:00:5e:00:53:aa", gw_mac=GW_MAC_ALT)
        attrs = attributions_for(before, back, 5.0, 5.0, anchor=before, link_gap=True)
        state = baseline.update_counters({"icmp_gw": True}, back, attrs, 5.0, 5.0,
                                         disrupted="link_restart")
        f = by_kind(run_all(before, back, _ctx(attrs, state, cur=back)), "GW_MAC_CHANGED")
        self.assertIsNotNone(f)
        self.assertIsNone(f.attribution, "링크 단절이 정체성 변화를 덮으면 안 된다")

    def test_the_window_opens_even_when_the_ssid_is_known(self):
        state = baseline.update_counters({}, obs(ssid=SSID), [], 5.0, 5.0,
                                         disrupted="link_restart")
        self.assertEqual(state.get("settle_reason"), "link_restart")
        self.assertTrue(state.get("settle_left_s"))

    def test_no_gap_opens_no_window(self):
        state = baseline.update_counters({}, obs(ssid=SSID), [], 5.0, 5.0)
        self.assertIsNone(state.get("settle_reason"))

    def test_a_deeper_cause_still_wins_over_the_gap(self):
        # 잠자기에서 깨어나느라 링크가 끊긴 것이면 근본 원인은 잠자기다.
        state = baseline.update_counters({}, obs(ssid=SSID), ["sleep"], 5.0, 5.0,
                                         disrupted="link_restart")
        self.assertEqual(state.get("settle_reason"), "sleep")


class TestVpnChangeDoesNotExcuseAnArpFlood(unittest.TestCase):
    """터널이 오르내린다고 세그먼트에 ARP 응답이 쏟아지지는 않는다."""

    def _spike(self, settle_reason):
        prev = obs(ssid=SSID, arp_replies=100000)
        cur = obs(ssid=SSID, arp_replies=100400)      # 5초에 400건
        state = {"icmp_gw": True, "arp_reply_rate": 0.8,
                 "settle_left_s": 40.0, "settle_reason": settle_reason}
        return by_kind(run_all(prev, cur, _ctx([], state, cur=cur)), "ARP_REPLY_SPIKE")

    def test_vpn_change_leaves_the_spike_standing(self):
        f = self._spike("vpn_change")
        self.assertIsNotNone(f)
        self.assertIsNone(f.attribution,
                          "VPN 전환을 ARP 폭주의 설명으로 쓰면 스푸핑을 숨길 창이 열린다")

    def test_a_link_restart_does_explain_it(self):
        # 재접속 직후에 ARP 를 몰아치는 것은 정상이다.
        self.assertEqual(self._spike("link_restart").attribution, "link_restart")

    def test_a_network_change_does_explain_it(self):
        self.assertEqual(self._spike("network_change").attribution, "network_change")

    def test_the_spike_is_recorded_either_way(self):
        for reason in ("vpn_change", "link_restart"):
            with self.subTest(reason=reason):
                self.assertIsNotNone(self._spike(reason), "억제는 삭제가 아니다")


if __name__ == "__main__":
    unittest.main()
