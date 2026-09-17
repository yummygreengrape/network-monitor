"""DHCP 가 밀어 넣은 경로와 터널 우회 (CVE-2024-3661, TunnelVision).

기본 경로만 보면 터널이 멀쩡해 보이는데 트래픽은 밖으로 나간다. netmon 은
`VPN_PROTECTION_LOST`("터널이 끊겨 밖으로 나감")를 갖고 있었지만, 터널이
살아 있는 채로 같은 결과가 나는 이 경로에는 눈이 없었다.

값은 전부 문서용 대역이다.
"""
from __future__ import annotations

import unittest

from netmon import messages as msg
from netmon.collect.dhcp import decode_classless_routes, static_routes_from
from netmon.collect.route import parse_route_get_match
from netmon.detect import Context, network_key, run_all
from tests.helpers import by_kind, kinds, obs

ON = {k: True for k in ("detect.l2", "detect.dhcp", "detect.dns", "detect.route",
                        "detect.wifi", "detect.quality", "detect.vpn")}

# 192.0.2.0/24 via 198.51.100.1  (RFC 3442 와이어 포맷)
WIRE_ONE = "18c00002c6336401"
# 0.0.0.0/0 via 198.51.100.1  — 프리픽스 길이 0, 유효 옥텟 0개. 가장 강한 형태.
WIRE_DEFAULT = "00c6336401"


def _ctx(cur, attrs=None):
    return Context(elapsed=5.0, interval=5.0, features=ON,
                   state={"icmp_gw": True}, attributions=attrs or [],
                   network=network_key(cur))


class TestRfc3442Decoder(unittest.TestCase):
    def test_single_route(self):
        self.assertEqual(decode_classless_routes(WIRE_ONE),
                         [{"dest": "192.0.2.0/24", "gateway": "198.51.100.1"}])

    def test_zero_length_prefix_is_a_default_route(self):
        # 프리픽스 길이 0 은 유효 옥텟이 0개다. 이것이 터널 우회의 가장 강한 형태다.
        self.assertEqual(decode_classless_routes(WIRE_DEFAULT),
                         [{"dest": "0.0.0.0/0", "gateway": "198.51.100.1"}])

    def test_several_routes_in_one_option(self):
        got = decode_classless_routes(WIRE_ONE + WIRE_DEFAULT)
        self.assertEqual([r["dest"] for r in got], ["192.0.2.0/24", "0.0.0.0/0"])

    def test_accepts_0x_and_spaced_forms(self):
        for form in ("0x" + WIRE_ONE, "18 c0 00 02 c6 33 64 01"):
            with self.subTest(form=form):
                self.assertEqual(decode_classless_routes(form)[0]["dest"], "192.0.2.0/24")

    def test_accepts_colon_separated_form(self):
        # 6옥텟 콜론 형태는 MAC 과 구분이 안 되어 누출 점검에 걸린다.
        # 여기서는 5옥텟짜리(기본 경로 항목)로 콜론 처리만 확인한다.
        self.assertEqual(decode_classless_routes("00:c6:33:64:01")[0]["dest"], "0.0.0.0/0")

    def test_unreadable_returns_none_not_empty(self):
        # None 과 [] 를 구분하지 않으면 "못 읽음"이 "없음"으로 둔갑한다.
        for bad in ("hex 아님", "18c000", "", "ff00000000"):
            with self.subTest(bad=bad):
                self.assertIsNone(decode_classless_routes(bad))


class TestStaticRouteCollection(unittest.TestCase):
    def test_absent_option(self):
        # 평시에는 최소 형태만 기록한다. 주기당 바이트가 하루치로는 커진다.
        got = static_routes_from({"router": ["192.0.2.1"]})
        self.assertEqual(got, {"present": False})
        self.assertTrue(got.get("parsed", True), "읽는 쪽은 기본값으로 동작해야 한다")

    def test_present_and_parsed(self):
        got = static_routes_from({"classless_static_route": WIRE_ONE})
        self.assertTrue(got["present"])
        self.assertTrue(got["parsed"])
        self.assertEqual(got["routes"][0]["dest"]["v"], "192.0.2.0/24")

    def test_present_but_unreadable_is_not_reported_as_absent(self):
        got = static_routes_from({"classless_static_route": "알 수 없는 형식"})
        self.assertTrue(got["present"], "옵션이 왔다는 사실은 남아야 한다")
        self.assertFalse(got["parsed"])
        self.assertEqual(got["routes"], [])

    def test_microsoft_and_classful_variants_are_recognised(self):
        for name in ("ms_classless_static_route", "option_249", "static_route", "option_121"):
            with self.subTest(option=name):
                self.assertTrue(static_routes_from({name: WIRE_ONE})["present"])


class TestRouteGetParsing(unittest.TestCase):
    def test_reads_interface_and_matched_destination(self):
        text = ("   route to: 192.0.2.1\ndestination: 192.0.2.0\n"
                "  interface: utun8\n     flags: <UP>")
        self.assertEqual(parse_route_get_match(text),
                         {"iface": "utun8", "destination": "192.0.2.0"})

    def test_fallthrough_to_default_is_visible(self):
        text = "   route to: default\ndestination: default\n  interface: en0\n"
        self.assertEqual(parse_route_get_match(text)["destination"], "default")

    def test_missing_lines_are_none(self):
        self.assertEqual(parse_route_get_match("   route to: 192.0.2.1\n"),
                         {"iface": None, "destination": None})


SR = {"present": True, "option": "classless_static_route", "parsed": True,
      "routes": [{"dest": {"id": "ipv4", "v": "192.0.2.0/24"},
                  "gateway": {"id": "ipv4", "v": "198.51.100.1"}}]}


class TestStaticRouteFinding(unittest.TestCase):
    def test_new_offer_is_reported(self):
        f = by_kind(run_all(obs(), obs(static_routes=SR), _ctx(obs())), "DHCP_STATIC_ROUTES")
        self.assertIsNotNone(f)
        self.assertEqual(f.axis, "security")
        self.assertEqual(f.summary, msg.DHCP_STATIC_ROUTES % 1)

    def test_unchanged_offer_is_silent(self):
        self.assertNotIn("DHCP_STATIC_ROUTES",
                         kinds(run_all(obs(static_routes=SR), obs(static_routes=SR), _ctx(obs()))))

    def test_unreadable_option_says_so(self):
        bad = dict(SR, parsed=False, routes=[])
        f = by_kind(run_all(obs(), obs(static_routes=bad), _ctx(obs())), "DHCP_STATIC_ROUTES")
        self.assertEqual(f.summary, msg.DHCP_STATIC_ROUTES_UNREAD)

    def test_moving_networks_attributes_but_keeps_the_record(self):
        f = by_kind(run_all(obs(), obs(static_routes=SR), _ctx(obs(), ["network_change"])),
                    "DHCP_STATIC_ROUTES")
        self.assertEqual(f.attribution, "network_change")
        self.assertEqual(f.severity, "low")


class TestTunnelBypass(unittest.TestCase):
    def _cur(self, egress_iface, tunnels=("utun8",)):
        return obs(static_routes=SR, tunnel_default=tunnels,
                   offered_egress=[("192.0.2.0/24", egress_iface)])

    def test_offered_prefix_leaving_outside_the_tunnel_is_high(self):
        cur = self._cur("en0")
        f = by_kind(run_all(obs(), cur, _ctx(cur)), "TUNNEL_BYPASS_ROUTE")
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.axis, "security")

    def test_prefix_inside_the_tunnel_is_silent(self):
        cur = self._cur("utun8")
        self.assertNotIn("TUNNEL_BYPASS_ROUTE", kinds(run_all(obs(), cur, _ctx(cur))))

    def test_no_tunnel_default_means_nothing_to_bypass(self):
        cur = self._cur("en0", tunnels=())
        self.assertNotIn("TUNNEL_BYPASS_ROUTE", kinds(run_all(obs(), cur, _ctx(cur))))

    def test_moving_networks_does_not_excuse_it(self):
        # 새 네트워크라도 DHCP 가 준 대역이 터널 밖으로 나가는 것은 사실이다.
        cur = self._cur("en0")
        f = by_kind(run_all(obs(), cur, _ctx(cur, ["network_change"])), "TUNNEL_BYPASS_ROUTE")
        self.assertIsNone(f.attribution)

    def test_fallthrough_to_the_default_is_not_called_a_bypass(self):
        """제공된 대역이 설치되지 않으면 조회가 기본 경로로 떨어진다.

        이 기기에서 기본 경로는 물리 인터페이스(en0)인데 실제 트래픽은
        터널로 간다. 매칭 경로를 안 보면 없는 우회를 만들어 낸다.
        """
        cur = obs(static_routes=SR, tunnel_default=("utun8",))
        cur.data["route"]["offered_egress"] = [
            {"dest": {"id": "ipv4", "v": "192.0.2.0/24"}, "iface": "en0",
             "matched_default": True}]
        self.assertNotIn("TUNNEL_BYPASS_ROUTE", kinds(run_all(obs(), cur, _ctx(cur))))

    def test_not_repeated_every_cycle(self):
        cur = self._cur("en0")
        self.assertNotIn("TUNNEL_BYPASS_ROUTE", kinds(run_all(cur, cur, _ctx(cur))))


if __name__ == "__main__":
    unittest.main()
