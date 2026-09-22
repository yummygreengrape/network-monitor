"""도달성 보정.

실측에서 확인한 상황을 재현한다: 게이트웨이가 ICMP 에 전혀 응답하지 않는데
ARP 는 정상이고 인터넷도 정상. 이 네트워크에서 ping 을 장애 기준으로 쓰면
매 주기가 장애가 된다.
"""
from __future__ import annotations

import unittest

from netmon import baseline
from netmon.liveness import (ARP, CALIBRATION_CYCLES, ICMP, LINK, UNKNOWN,
                             REVERT_AFTER_ICMP_FAILURES, evaluate)
from tests.helpers import GW_MAC, obs


def cycles(n, **kw):
    state = {}
    decided = []
    for i in range(n):
        o = obs(ts="2026-01-01T00:00:%02dZ" % i, **kw)
        state = baseline.update_counters(state, o)
        decided.append(state.get("_liveness_decided"))
        state = baseline.update_baselines(state, o)
    return state, decided


class TestIcmpSilentGateway(unittest.TestCase):
    def test_concludes_icmp_unusable_after_calibration(self):
        state, decided = cycles(CALIBRATION_CYCLES + 2, icmp_ok=False, gw_mac=GW_MAC)
        self.assertIs(state["icmp_gw"], False)
        self.assertEqual(decided.count(ARP), 1, "결론은 한 번만 기록한다")
        self.assertEqual(state["gw_fail_streak"], 0,
                         "ARP 가 살아 있으므로 실패로 세지 않는다")

    def test_no_false_unreachable_before_calibration(self):
        state, _ = cycles(CALIBRATION_CYCLES - 1, icmp_ok=False, gw_mac=GW_MAC)
        self.assertIsNone(state.get("icmp_gw"))
        self.assertEqual(state["gw_fail_streak"], 0)

    def test_arp_loss_is_a_real_failure_even_when_icmp_is_unusable(self):
        state, _ = cycles(CALIBRATION_CYCLES + 1, icmp_ok=False, gw_mac=GW_MAC)
        for i in range(3):
            o = obs(ts="2026-01-01T00:01:%02dZ" % i, icmp_ok=False, gw_mac=None)
            state = baseline.update_counters(state, o)
        self.assertEqual(state["gw_fail_streak"], 3)
        method, alive = evaluate(obs(icmp_ok=False, gw_mac=None), state)
        self.assertEqual(method, ARP)
        self.assertFalse(alive)


class TestIcmpCapableGateway(unittest.TestCase):
    def test_first_reply_settles_icmp_mode(self):
        state, decided = cycles(3, icmp_ok=True)
        self.assertIs(state["icmp_gw"], True)
        self.assertEqual(decided[0], ICMP)
        self.assertEqual(decided[1:], [None, None])

    def test_icmp_failure_counts_once_icmp_is_the_method(self):
        state, _ = cycles(2, icmp_ok=True)
        for i in range(2):
            o = obs(ts="2026-01-01T00:02:%02dZ" % i, icmp_ok=False, gw_mac=GW_MAC)
            state = baseline.update_counters(state, o)
        self.assertEqual(state["gw_fail_streak"], 2,
                         "ICMP 를 쓰는 네트워크에서는 ICMP 실패가 곧 실패다")


class TestIcmpModeCanBeRevoked(unittest.TestCase):
    """한번 ICMP 로 정하면 영원히 그대로면, 게이트웨이가 ICMP 속도 제한을 켠
    순간부터 거짓 경보가 끝나지 않는다."""

    def _run(self, state, n, **kw):
        for i in range(n):
            o = obs(ts="2026-01-01T01:%02d:00Z" % (i % 60), **kw)
            state = baseline.update_counters(state, o)
            decided = state.get("_liveness_decided")
            state = baseline.update_baselines(state, o)
            if decided:
                state["_last_decided"] = decided
        return state

    def test_reverts_to_arp_when_icmp_stops_but_arp_stays_healthy(self):
        state, _ = cycles(2, icmp_ok=True)
        self.assertIs(state["icmp_gw"], True)
        state = self._run(state, REVERT_AFTER_ICMP_FAILURES, icmp_ok=False, gw_mac=GW_MAC)
        self.assertIs(state["icmp_gw"], False)
        self.assertEqual(state.get("_last_decided"), ARP)

    def test_does_not_revert_while_arp_is_also_down(self):
        """ARP 까지 죽은 것은 진짜 장애다. 기준을 바꿔서 덮으면 안 된다."""
        state, _ = cycles(2, icmp_ok=True)
        state = self._run(state, REVERT_AFTER_ICMP_FAILURES + 5,
                          icmp_ok=False, gw_mac=None)
        self.assertIs(state["icmp_gw"], True)
        self.assertGreaterEqual(state["gw_fail_streak"], REVERT_AFTER_ICMP_FAILURES)

    def test_a_single_reply_clears_the_failure_run(self):
        state, _ = cycles(2, icmp_ok=True)
        state = self._run(state, REVERT_AFTER_ICMP_FAILURES - 1, icmp_ok=False, gw_mac=GW_MAC)
        state = self._run(state, 1, icmp_ok=True)
        self.assertEqual(state.get("icmp_fail_run", 0), 0)
        self.assertIs(state["icmp_gw"], True)


class TestCalibratingDoesNotAlwaysHold(unittest.TestCase):
    """보정 중이라고 늘 판정을 미루는 것은 아니다.

    ARP 도 ICMP 도 살아 있다고 말하지 않는 입력에서, 링크 자체가 내려가
    있으면 `(LINK, False)` 로 **판정한다.** 링크 신호가 없거나 켜져 있을
    때만 보류한다(None). `collect/link.first_hop_silent` 는 이 갈래와 일부러
    갈라지는데, 그 주석이 "liveness 는 판정을 보류한다" 고만 적고 있었다 —
    갈라지는 지점을 적을 때 쓰는 근거이므로 여기서 값으로 못 박는다.
    """

    def test_a_dead_link_while_calibrating_is_a_verdict(self):
        self.assertEqual(
            evaluate(obs(icmp_ok=False, gw_mac=None, link_active="FALSE"), {}),
            (LINK, False))

    def test_the_same_input_with_the_link_up_is_held(self):
        self.assertEqual(
            evaluate(obs(icmp_ok=False, gw_mac=None, link_active="TRUE"), {}),
            (UNKNOWN, None))


class TestNetworkChangeResetsCalibration(unittest.TestCase):
    def test_moving_networks_forgets_icmp_conclusion(self):
        state, _ = cycles(CALIBRATION_CYCLES + 1, icmp_ok=False, gw_mac=GW_MAC)
        self.assertIs(state["icmp_gw"], False)
        fresh = baseline.reset_for_new_network(state)
        self.assertIsNone(fresh.get("icmp_gw"),
                          "다른 네트워크의 게이트웨이는 다르게 동작한다")
        self.assertIsNone(fresh.get("rtt_ewma"))


class TestBaselineOrdering(unittest.TestCase):
    def test_current_spike_is_not_folded_into_its_own_baseline(self):
        """급변이 자기 기준선에 섞이면 스스로 묻힌다."""
        state = {}
        for i in range(5):
            o = obs(ts="2026-01-01T00:00:%02dZ" % i, icmp_ok=True, rtt=3.0)
            state = baseline.update_counters(state, o)
            state = baseline.update_baselines(state, o)
        before = state["rtt_ewma"]
        spike = obs(ts="2026-01-01T00:00:09Z", icmp_ok=True, rtt=300.0)
        judged_with = baseline.update_counters(state, spike)
        self.assertEqual(judged_with["rtt_ewma"], before,
                         "판정 시점의 기준선에는 이번 값이 없어야 한다")


if __name__ == "__main__":
    unittest.main()
