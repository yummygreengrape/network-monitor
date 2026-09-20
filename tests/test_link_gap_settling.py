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
from netmon import messages as msg
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


class TestLeaseRenewalDoesNotInventALinkDrop(unittest.TestCase):
    """임대는 링크가 멀쩡해도 T1 에서 주기적으로 갱신된다.

    2026-09-17 02:47:56 에 유선 데스크톱에서 실제로 난 일. 임대 시작이
    정확히 36시간 간격으로 바뀌었는데(전형적 T1 갱신, 그날 LINK_ABSENT 는
    한 건도 없었음) "링크가 한 번 끊겼다 다시 붙었다는 뜻" 이 붙었다.
    """
    def _renewal(self, state=None, attrs=None):
        prev = obs(ssid=SSID, lease_start="2026-09-15 23:47:57")
        cur = obs(ssid=SSID, lease_start="2026-09-17 11:47:57")
        state = dict(state or {}); state.setdefault("icmp_gw", True)
        return by_kind(run_all(prev, cur, _ctx(attrs or [], state, cur=cur)),
                       "DHCP_LEASE_RENEWED")

    def test_a_quiet_renewal_does_not_claim_a_link_drop(self):
        f = self._renewal()
        self.assertEqual(f.summary, msg.DHCP_LEASE_RENEWED)
        self.assertNotIn("끊겼다", f.summary)

    def test_a_renewal_inside_the_settling_window_does_say_so(self):
        f = self._renewal(state={"settle_left_s": 40.0, "settle_reason": "link_restart"})
        self.assertEqual(f.summary, msg.DHCP_LEASE_RENEWED_AFTER_LINK)

    def test_a_renewal_after_moving_does_say_so(self):
        self.assertEqual(self._renewal(attrs=["network_change"]).summary,
                         msg.DHCP_LEASE_RENEWED_AFTER_LINK)

    def test_a_vpn_settling_window_is_not_evidence_of_a_link_drop(self):
        f = self._renewal(state={"settle_left_s": 40.0, "settle_reason": "vpn_change"})
        self.assertEqual(f.summary, msg.DHCP_LEASE_RENEWED)

    def test_a_measurement_gap_is_not_evidence_of_a_link_drop(self):
        """2026-09-20 맥북: 임대 갱신 4건에 "링크가 끊겼다 다시 붙었다" 가 붙었는데,
        공백 전후 샘플은 모두 link_active 였고 LINK_ABSENT 는 0건이었다.
        sleep 은 "측정 간격이 임계를 넘었다" 는 뜻뿐이고, launchd 가 프로세스만
        되살린 경우에도 붙는다."""
        f = self._renewal(state={"settle_left_s": 40.0, "settle_reason": "sleep"})
        self.assertEqual(f.summary, msg.DHCP_LEASE_RENEWED_AFTER_GAP)
        self.assertNotIn("끊겼다", f.summary)

    def test_the_gap_wording_says_the_link_was_not_observed(self):
        f = self._renewal(state={"settle_left_s": 40.0, "settle_reason": "sleep"})
        self.assertIn("관측되지 않았", f.summary)

    def test_an_observed_link_gap_outranks_a_measurement_gap(self):
        """잠자기와 관측된 링크 단절이 같은 창에 겹치면 settle_reason 은 sleep 만
        남는다(baseline.DISRUPTIONS 순서). 그래도 LINK_ABSENT 를 실제로 본 주기이므로
        "관측되지 않았음" 이라고 말하면 안 된다. 상태는 baseline 규칙으로 직접 만든다."""
        state = baseline.update_counters(
            {"icmp_gw": True}, obs(ssid=SSID), attributions=["sleep"],
            elapsed=600, interval=5, disrupted="link_restart")
        self.assertEqual(state.get("settle_reason"), "sleep")
        f = self._renewal(state=state)
        self.assertEqual(f.summary, msg.DHCP_LEASE_RENEWED_AFTER_LINK)

    def test_a_new_network_forgets_the_observed_link_gap(self):
        """옮긴 뒤의 갱신이 옛 네트워크에서 본 단절을 근거로 말하면 안 된다."""
        self.assertIn("settle_saw_link_gap", baseline.VOLATILE_KEYS)
        cleared = baseline.reset_for_new_network({"settle_saw_link_gap": True,
                                                  "settle_left_s": 40.0,
                                                  "settle_reason": "sleep"})
        self.assertNotIn("settle_saw_link_gap", cleared)

    def test_a_closed_window_forgets_the_observed_link_gap(self):
        state = baseline.update_counters(
            {"icmp_gw": True}, obs(ssid=SSID), attributions=["sleep"],
            elapsed=600, interval=5, disrupted="link_restart")
        for _ in range(12):  # 창(45초)이 닫힐 때까지 조용한 주기를 흘려보낸다
            state = baseline.update_counters(state, obs(ssid=SSID), attributions=[],
                                             elapsed=5, interval=5)
        self.assertIsNone(state.get("settle_saw_link_gap"))
        self.assertEqual(self._renewal(state=state).summary, msg.DHCP_LEASE_RENEWED)

    def test_moving_still_outranks_a_measurement_gap(self):
        f = self._renewal(attrs=["network_change"],
                          state={"settle_left_s": 40.0, "settle_reason": "sleep"})
        self.assertEqual(f.summary, msg.DHCP_LEASE_RENEWED_AFTER_LINK)
