"""커널이 남기는 ARP MAC 치환 기록.

폴링은 "지금 값"만 본다. 두 주기 사이에 바뀌었다가 되돌아간 치환은 캐시에
흔적이 없다. 커널 로그는 그 순간을 옛 MAC·새 MAC 과 함께 남긴다.

기본값 macOS 에서는 `net.link.ether.inet.log_arp_warnings` 가 0 이라 아무것도
기록되지 않는다 — 이 기기에서 24시간 `arp:` 커널 메시지 0건을 확인했다.
값은 전부 문서용 대역이다.
"""
from __future__ import annotations

import unittest

from netmon.collect.arp import parse_arp_log
from netmon.detect import Context, network_key, run_all
from tests.helpers import GW_MAC, GW_MAC_ALT, by_kind, kinds, obs

ON = {k: True for k in ("detect.l2", "detect.dhcp", "detect.dns", "detect.route",
                        "detect.wifi", "detect.quality", "detect.vpn")}

MOVED = ("2026-01-01 00:00:01.100 Df kernel[0:1] arp: 192.0.2.50 moved from "
         "00:00:5e:00:53:07 to 00:00:5e:00:53:08 on en0")
MOVED_GW = ("2026-01-01 00:00:02.200 Df kernel[0:1] arp: 192.0.2.1 moved from "
            "00:00:5e:00:53:01 to 00:00:5e:00:53:02 on en0")
PERM = ("2026-01-01 00:00:03.300 Df kernel[0:1] arp: 00:00:5e:00:53:09 attempts to "
        "modify permanent entry for 192.0.2.1 on en0")


def _ctx(cur, state=None):
    return Context(elapsed=5.0, interval=5.0, features=ON,
                   state=state if state is not None else {"icmp_gw": True},
                   attributions=[], network=network_key(cur))


class TestParsing(unittest.TestCase):
    def test_moved_line(self):
        e = parse_arp_log(MOVED)[0]
        self.assertEqual(e["kind"], "moved")
        self.assertEqual(e["ts"], "2026-01-01 00:00:01.100")
        self.assertEqual(e["prev"]["v"], "00:00:5e:00:53:07")
        self.assertEqual(e["cur"]["v"], "00:00:5e:00:53:08")
        self.assertEqual(e["iface"], "en0")

    def test_permanent_entry_line(self):
        e = parse_arp_log(PERM)[0]
        self.assertEqual(e["kind"], "permanent_denied")
        self.assertEqual(e["cur"]["v"], "00:00:5e:00:53:09")

    def test_unknown_arp_line_is_kept_not_dropped(self):
        e = parse_arp_log("2026-01-01 00:00:04.400 Df kernel[0:1] arp: 처음 보는 형태")[0]
        self.assertEqual(e["kind"], "unparsed")
        self.assertIn("처음 보는 형태", e["raw"])

    def test_non_arp_lines_ignored(self):
        self.assertEqual(parse_arp_log("2026-01-01 00:00:05.500 Df kernel[0:1] warp-cli[1] x"), [])

    def test_short_form_macs_are_normalised(self):
        line = ("2026-01-01 00:00:06.600 Df kernel[0:1] arp: 192.0.2.50 moved from "
                "0:0:5e:0:53:7 to 0:0:5e:0:53:8 on en0")
        self.assertEqual(parse_arp_log(line)[0]["prev"]["v"], "00:00:5e:00:53:07")


class TestFindings(unittest.TestCase):
    def test_substitution_is_reported(self):
        cur = obs(arp_log=parse_arp_log(MOVED))
        f = by_kind(run_all(obs(), cur, _ctx(cur)), "ARP_MAC_SUBSTITUTED")
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, "medium")
        self.assertIsNone(f.attribution, "커널이 기록한 사실은 이동으로 설명되지 않는다")

    def test_gateway_substitution_is_higher(self):
        cur = obs(gw_mac=GW_MAC_ALT, arp_log=parse_arp_log(MOVED_GW))
        f = by_kind(run_all(obs(), cur, _ctx(cur)), "ARP_MAC_SUBSTITUTED")
        self.assertEqual(f.severity, "high")

    def test_permanent_entry_attempt_is_high(self):
        cur = obs(arp_log=parse_arp_log(PERM))
        self.assertEqual(by_kind(run_all(obs(), cur, _ctx(cur)),
                                 "ARP_PERMANENT_DENIED").severity, "high")

    def test_overlapping_windows_do_not_repeat(self):
        # 창이 60초마다 90초를 보므로 같은 사건이 두 번 들어온다.
        state = {"icmp_gw": True}
        cur = obs(arp_log=parse_arp_log(MOVED))
        ctx = _ctx(cur, state)
        self.assertIn("ARP_MAC_SUBSTITUTED", kinds(run_all(obs(), cur, ctx)))
        ctx2 = _ctx(cur, state)
        self.assertNotIn("ARP_MAC_SUBSTITUTED", kinds(run_all(obs(), cur, ctx2)))

    def test_a_genuinely_new_event_still_fires(self):
        state = {"icmp_gw": True}
        first = obs(arp_log=parse_arp_log(MOVED))
        run_all(obs(), first, _ctx(first, state))
        second = obs(arp_log=parse_arp_log(MOVED + "\n" + MOVED_GW))
        self.assertIn("ARP_MAC_SUBSTITUTED", kinds(run_all(obs(), second, _ctx(second, state))))

    def test_seen_list_is_bounded(self):
        state = {"icmp_gw": True}
        for i in range(300):
            line = ("2026-01-01 00:00:%02d.%03d Df kernel[0:1] arp: 192.0.2.50 moved from "
                    "00:00:5e:00:53:07 to 00:00:5e:00:53:08 on en0" % (i % 60, i))
            cur = obs(arp_log=parse_arp_log(line))
            run_all(obs(), cur, _ctx(cur, state))
        self.assertLessEqual(len(state["arp_log_seen"]), 200)

    def test_no_log_events_is_silent(self):
        self.assertNotIn("ARP_MAC_SUBSTITUTED", kinds(run_all(obs(), obs(), _ctx(obs()))))


if __name__ == "__main__":
    unittest.main()
