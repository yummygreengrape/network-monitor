"""실측 로그를 읽다가 드러난 결함들.

전부 상시 실행 기록에서 실제로 나온 일이다. 합성 입력만으로는 보이지 않았다.
"""
from __future__ import annotations

import unittest

from netmon import baseline
from netmon.collect.arp import normalize_mac, parse_arp_table
from netmon.detect import Context, attributions_for, network_key, run_all
from tests.helpers import GW_MAC, GW_MAC_ALT, by_kind, kinds, obs, vpn_state

ON = {k: True for k in ("detect.l2", "detect.dhcp", "detect.dns", "detect.route",
                        "detect.wifi", "detect.quality", "detect.vpn")}


def judge(prev, cur, state=None, elapsed=5.0):
    attrs = attributions_for(prev, cur, elapsed, 5.0)
    ctx = Context(elapsed=elapsed, interval=5.0, features=ON,
                  state=state or {"icmp_gw": True}, attributions=attrs,
                  network=network_key(cur))
    return run_all(prev, cur, ctx)


class TestArpSpikeAfterSleep(unittest.TestCase):
    """2026-09-16 05:30:38 에 실제로 난 거짓 경보.

    잠자기로 939초가 벌어진 구간의 누적 카운터 증가분(62)을 5초 주기의
    증가분(평균 4.1)과 같은 잣대로 비교해 "평소의 15배"라고 알렸다.
    초당으로 환산하면 0.066 대 0.82 로 오히려 평소보다 낮았다.
    """

    def test_the_original_false_positive_no_longer_fires(self):
        prev = obs(ts="2026-09-16T05:14:59Z", arp_replies=100000)
        cur = obs(ts="2026-09-16T05:30:38Z", arp_replies=100062)
        found = judge(prev, cur, state={"icmp_gw": True, "arp_reply_rate": 0.82},
                      elapsed=939.0)
        self.assertIsNone(by_kind(found, "ARP_REPLY_SPIKE"),
                          "측정이 벌어진 구간의 증가분을 급증으로 읽으면 안 된다")

    def test_a_real_burst_at_normal_cadence_still_fires(self):
        prev = obs(ts="2026-09-16T05:14:54Z", arp_replies=100000)
        cur = obs(ts="2026-09-16T05:14:59Z", arp_replies=100400)   # 5초에 400건
        f = by_kind(judge(prev, cur, state={"icmp_gw": True, "arp_reply_rate": 0.82}),
                    "ARP_REPLY_SPIKE")
        self.assertIsNotNone(f)
        self.assertEqual(f.evidence["per_second"], 80.0)
        self.assertEqual(f.confidence, "suspect")

    def test_baseline_is_kept_per_second_not_per_cycle(self):
        state = {}
        for i in range(4):
            o = obs(ts="2026-01-01T00:00:%02dZ" % (i * 5), arp_replies=1000 + i * 4)
            state = baseline.update_baselines(state, o, elapsed=5.0)
        self.assertLess(state["arp_reply_rate"], 2.0,
                        "주기당 4건은 초당 0.8건이다")

    def test_a_long_gap_does_not_inflate_the_baseline(self):
        state = {"arp_replies_last": 1000, "arp_reply_rate": 0.8}
        after = baseline.update_baselines(
            state, obs(arp_replies=1062), elapsed=939.0)
        self.assertLess(after["arp_reply_rate"], 0.8)


class TestLatencyNoise(unittest.TestCase):
    """한 시간에 아홉 번 뜨던 LATENCY_SPIKE.

    무선 구간은 한 번씩 튀는 것이 정상이다. 연속으로 높을 때만 알린다.
    """

    def _run(self, rtts, base=15.0):
        state = {"icmp_gw": True, "rtt_ewma": base}
        prev = obs(ts="2026-01-01T00:00:00Z", icmp_ok=True, rtt=base)
        fired = 0
        for i, rtt in enumerate(rtts, start=1):
            cur = obs(ts="2026-01-01T00:0%d:00Z" % min(i, 9), icmp_ok=True, rtt=rtt)
            state = baseline.update_counters(state, cur)
            ctx = Context(elapsed=5.0, interval=5.0, features=ON, state=state,
                          attributions=[], network=network_key(cur))
            if by_kind(run_all(prev, cur, ctx), "LATENCY_SPIKE"):
                fired += 1
            state = dict(state, rtt_ewma=base)   # 기준선은 고정해서 비교
            prev = cur
        return fired

    def test_a_single_jitter_spike_is_not_reported(self):
        self.assertEqual(self._run([80.0]), 0)
        self.assertEqual(self._run([80.0, 14.0, 90.0, 12.0]), 0,
                         "튀었다 돌아오는 것은 무선 구간의 정상 동작이다")

    def test_sustained_elevation_is_reported_once(self):
        self.assertEqual(self._run([80.0, 90.0, 85.0]), 1)
        self.assertEqual(self._run([80.0, 90.0, 85.0, 88.0, 92.0]), 1,
                         "지속되는 동안 매 주기 알리면 그것도 소음이다")

    def test_recovery_then_a_new_run_reports_again(self):
        self.assertEqual(self._run([80.0, 90.0, 85.0, 12.0, 80.0, 90.0, 85.0]), 2)


class TestMacNormalisation(unittest.TestCase):
    """macOS arp 는 각 옥텟의 앞 0 을 떼고 출력한다 (0:0:5e:0:53:1).

    실측 기록에 그대로 남아 있었다. 그 표기는 누출 검사의 MAC 패턴에도
    걸리지 않아 저장소로 새어 들어갈 수 있었다.
    """

    def test_short_form_is_padded(self):
        self.assertEqual(normalize_mac("0:0:5e:0:53:1"), "00:00:5e:00:53:01")

    def test_case_is_folded(self):
        self.assertEqual(normalize_mac("0:0:5E:0:53:A"), "00:00:5e:00:53:0a")

    def test_full_form_is_unchanged(self):
        self.assertEqual(normalize_mac("00:00:5e:00:53:01"), "00:00:5e:00:53:01")

    def test_nonsense_is_left_alone_rather_than_guessed(self):
        self.assertEqual(normalize_mac("(incomplete)"), "(incomplete)")
        self.assertEqual(normalize_mac("nope"), "nope")

    def test_parser_normalises(self):
        rows = parse_arp_table(
            "Neighbor Linklayer Address Expire(O) Expire(I) Netif\n"
            "192.0.2.1  0:0:5e:0:53:1  1m  1m  en0\n")
        self.assertEqual(rows[0]["mac"], "00:00:5e:00:53:01")

    def test_the_two_spellings_do_not_look_like_a_change(self):
        """정규화하지 않으면 같은 주소가 바뀐 것처럼 보인다."""
        self.assertEqual(normalize_mac("0:0:5e:0:53:1"), normalize_mac("00:00:5e:00:53:01"))


class TestInvestigationDoesNotOverclaim(unittest.TestCase):
    """ARP 급증으로 열린 조사가 "접속점 교체로 추정" 이라고 끝냈다.

    MAC 이 바뀐 적이 한 번도 없는데 교체를 주장한 것이다.
    """

    def _watch(self, trigger_obs, cycles=22):
        from netmon import investigate
        from netmon import messages as msg

        state = {"icmp_gw": True, "arp_reply_rate": 0.82}
        inv = investigate.Investigator({})
        prev = obs(ts="2026-01-01T00:00:00Z", gw_mac=GW_MAC, arp_replies=1000)
        found_all = []
        cur = trigger_obs
        for i in range(cycles):
            attrs = attributions_for(prev, cur, 5.0, 5.0)
            ctx = Context(elapsed=5.0, interval=5.0, features=ON, state=state,
                          attributions=attrs, network=network_key(cur))
            found = run_all(prev, cur, ctx)
            extra, _ = inv.run(prev, cur, ctx, found, state)
            found_all.extend(found + extra)
            prev = cur
            cur = obs(ts="2026-01-01T00:0%d:%02dZ" % ((i // 12) + 1, (i * 5) % 60),
                      gw_mac=GW_MAC, arp_replies=1000 + i)
        return investigate.Investigator.load(state), found_all

    def test_spike_triggered_investigation_does_not_claim_an_ap_swap(self):
        from netmon import messages as msg

        trigger = obs(ts="2026-01-01T00:00:05Z", gw_mac=GW_MAC, arp_replies=1400)
        invs, _ = self._watch(trigger)
        done = [i for i in invs if i.kind == "l2_identity" and not i.open]
        self.assertTrue(done, "조사가 결론을 내야 한다")
        self.assertEqual(done[0].trigger, "ARP_REPLY_SPIKE")
        self.assertEqual(done[0].verdict, msg.INV_L2_NO_CHANGE_VERDICT)
        self.assertFalse(done[0].criteria.get("mac_changed"))

    def test_mac_triggered_investigation_still_says_ap_swap(self):
        from netmon import messages as msg

        trigger = obs(ts="2026-01-01T00:00:05Z", gw_mac=GW_MAC_ALT, arp_replies=1001)
        invs, _ = self._watch(trigger)
        done = [i for i in invs if i.kind == "l2_identity" and not i.open]
        self.assertTrue(done)
        self.assertEqual(done[0].trigger, "GW_MAC_CHANGED")
        self.assertEqual(done[0].verdict, msg.INV_L2_STABLE_VERDICT)


if __name__ == "__main__":
    unittest.main()
