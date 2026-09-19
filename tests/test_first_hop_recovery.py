"""첫 홉 복구 판정이 한 번도 뜨지 않던 문제.

기준선 갱신(`baseline.update_counters`)이 판정(`run_all`)보다 먼저 돌면서
성공 주기에 `gw_fail_streak` 을 0 으로 만든다. 복구 분기는 그 값이 2 이상일
것을 요구했으므로 **조건이 영원히 거짓**이었다.

양쪽 기계 전체 기록에서 확인: FIRST_HOP_UNREACHABLE 10건, FIRST_HOP_RECOVERED 0건.
이 판정에는 테스트가 아예 없었다 — 그래서 아무도 잡지 못했다.
값은 전부 문서용 대역이다.
"""
from __future__ import annotations

import unittest

from netmon import baseline
from netmon.detect import Context, network_key, run_all
from tests.helpers import by_kind, kinds, obs

ON = {k: True for k in ("detect.l2", "detect.dhcp", "detect.dns", "detect.route",
                        "detect.wifi", "detect.quality", "detect.vpn")}


def _cycle(state, cur, prev):
    """엔진과 같은 순서: 기준선 갱신 → 판정."""
    state = baseline.update_counters(state, cur, [], 5.0, 5.0)
    ctx = Context(elapsed=5.0, interval=5.0, features=ON, state=state,
                  attributions=[], network=network_key(cur))
    return state, run_all(prev, cur, ctx)


def _up(ts):
    return obs(ts=ts, icmp_ok=True, rtt=3.0)


def _down(ts):
    return obs(ts=ts, icmp_ok=False, rtt=None)


class TestRecoveryFires(unittest.TestCase):
    def setUp(self):
        self.state = {"icmp_gw": True}

    def _run(self, seq):
        prev = _up("2026-01-01T00:00:00Z")
        self.state, _ = _cycle(self.state, prev, None)
        seen = []
        for i, alive in enumerate(seq, start=1):
            cur = (_up if alive else _down)("2026-01-01T00:00:%02dZ" % (i * 5))
            self.state, found = _cycle(self.state, cur, prev)
            seen.append(kinds(found))
            prev = cur
        return seen

    def test_outage_then_recovery_both_appear(self):
        seen = self._run([False, False, False, True])
        self.assertIn("FIRST_HOP_UNREACHABLE", seen[2], "세 번째 실패에서 알린다")
        self.assertIn("FIRST_HOP_RECOVERED", seen[3], "복구도 기록돼야 한다")

    def test_recovery_reports_how_long_it_was_down(self):
        prev = _up("2026-01-01T00:00:00Z")
        self.state, _ = _cycle(self.state, prev, None)
        for i in range(4):
            cur = _down("2026-01-01T00:00:%02dZ" % ((i + 1) * 5))
            self.state, _ = _cycle(self.state, cur, prev)
            prev = cur
        back = _up("2026-01-01T00:00:30Z")
        self.state, found = _cycle(self.state, back, prev)
        f = by_kind(found, "FIRST_HOP_RECOVERED")
        self.assertIsNotNone(f)
        self.assertEqual(f.evidence["streak"], 4, "끊겼던 주기 수를 그대로 말해야 한다")

    def test_a_two_cycle_gap_is_now_silent(self):
        # 2026-09-20: 10초짜리 공백이 30분마다 되풀이됐는데 같은 순간 외부 경로는
        # 멀쩡했다. 공유기의 ICMP 무시였지 연결 끊김이 아니었다.
        seen = self._run([False, False, True])
        self.assertFalse(any("FIRST_HOP_UNREACHABLE" in s for s in seen))
        self.assertFalse(any("FIRST_HOP_RECOVERED" in s for s in seen))

    def test_a_single_blip_does_not_log_recovery(self):
        # 한 주기만 실패한 것은 알리지도 않았으므로 복구도 알리지 않는다.
        seen = self._run([False, True])
        self.assertNotIn("FIRST_HOP_UNREACHABLE", seen[0])
        self.assertNotIn("FIRST_HOP_RECOVERED", seen[1])

    def test_recovery_is_not_repeated_while_healthy(self):
        seen = self._run([False, False, False, True, True, True])
        self.assertEqual(sum("FIRST_HOP_RECOVERED" in s for s in seen), 1)

    def test_a_second_outage_alerts_again(self):
        # 2026-09-17 14:39~14:41 실측: 끊김과 복구가 번갈아 반복됐다.
        seen = self._run([False, False, False, True, False, False, False, True])
        self.assertEqual(sum("FIRST_HOP_UNREACHABLE" in s for s in seen), 2)
        self.assertEqual(sum("FIRST_HOP_RECOVERED" in s for s in seen), 2)

    def test_counters_keep_the_pre_reset_value(self):
        st = baseline.update_counters({"icmp_gw": True, "gw_fail_streak": 3},
                                      _up("2026-01-01T00:00:05Z"), [], 5.0, 5.0)
        self.assertEqual(st["gw_fail_streak"], 0)
        self.assertEqual(st["gw_fail_streak_prev"], 3)

    def test_prev_value_clears_while_still_down(self):
        st = baseline.update_counters({"icmp_gw": True, "gw_fail_streak": 3},
                                      _down("2026-01-01T00:00:05Z"), [], 5.0, 5.0)
        self.assertEqual(st["gw_fail_streak"], 4)
        self.assertEqual(st["gw_fail_streak_prev"], 0)


if __name__ == "__main__":
    unittest.main()
