"""IPv6 라우터 "출현" 이 이미 본 라우터에 뜨던 문제.

직전 관측과만 비교해서, 이웃 표에서 잠깐 빠졌다 돌아온 라우터가 새 라우터로
판정됐다. 실측 이틀간 IPV6_ROUTER_APPEARED 2건이 전부 그랬고, 그중 하나는
OS 업데이트로 종료되던 순간의 이웃 표가 재시작 비교 기준으로 남아서였다.
값은 전부 문서용 대역이다.
"""
from __future__ import annotations

import unittest

from netmon import baseline
from netmon.detect import Context, network_key, run_all
from tests.helpers import kinds, obs

ON = {k: True for k in ("detect.l2", "detect.dhcp", "detect.dns", "detect.route",
                        "detect.wifi", "detect.quality", "detect.vpn")}
R1 = ("2001:db8::1", "en0")
R2 = ("2001:db8::2", "en0")


def _step(state, prev, cur):
    ctx = Context(elapsed=5.0, interval=5.0, features=ON, state=state,
                  attributions=[], network=network_key(cur))
    return kinds(run_all(prev, cur, ctx))


class TestKnownRouters(unittest.TestCase):
    def test_router_that_dropped_out_and_came_back_is_not_new(self):
        st = {"icmp_gw": True}
        both = obs(ipv6_routers=[R1, R2])
        one = obs(ipv6_routers=[R1])
        _step(st, both, both)
        _step(st, both, one)                       # 종료 중처럼 하나가 빠짐
        self.assertNotIn("IPV6_ROUTER_APPEARED", _step(st, one, both))

    def test_a_truly_new_router_still_fires(self):
        st = {"icmp_gw": True}
        one = obs(ipv6_routers=[R1])
        _step(st, one, one)
        self.assertIn("IPV6_ROUTER_APPEARED", _step(st, one, obs(ipv6_routers=[R1, R2])))

    def test_known_set_survives_via_state(self):
        # 재시작해도 state.json 에 남으므로, 복원된 기준이 부실해도 오탐하지 않는다.
        st = {"icmp_gw": True, "ipv6_routers_known": ["2001:db8::1", "2001:db8::2"]}
        self.assertNotIn("IPV6_ROUTER_APPEARED",
                         _step(st, obs(ipv6_routers=[R1]), obs(ipv6_routers=[R1, R2])))

    def test_moving_networks_forgets_the_old_routers(self):
        st = baseline.reset_for_new_network({"ipv6_routers_known": ["2001:db8::2"]})
        self.assertNotIn("ipv6_routers_known", st)

    def test_memory_is_bounded(self):
        st = {"icmp_gw": True}
        prev = obs(ipv6_routers=[R1])
        for i in range(100):
            cur = obs(ipv6_routers=[R1, ("2001:db8::%x" % (i + 16), "en0")])
            _step(st, prev, cur)
            prev = cur
        self.assertLessEqual(len(st["ipv6_routers_known"]), 64)


if __name__ == "__main__":
    unittest.main()
