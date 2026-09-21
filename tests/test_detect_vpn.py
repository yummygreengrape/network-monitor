"""VPN 판정 — 상태 전환과 끊김.

원본 스크립트는 끊김 원인을 하나만 골랐다. 여기서는 한 번의 끊김이 품질과
보안 두 축에 따로 기록되고, "왜"는 분류가 아니라 근거로 붙는다.
"""
from __future__ import annotations

import unittest

from netmon import messages as msg
from netmon import vpn as vpnmod
from netmon.detect import Context, attributions_for, network_key, run_all
from tests.helpers import GW_MAC, by_kind, kinds, obs, vpn_state

ON = {"detect.vpn": True, "detect.quality": True, "detect.l2": True,
      "detect.dhcp": True, "detect.dns": True, "detect.route": True,
      "detect.wifi": True}


def judge(prev, cur, state=None, elapsed=5.0):
    attrs = attributions_for(prev, cur, elapsed, 5.0)
    ctx = Context(elapsed=elapsed, interval=5.0, features=ON,
                  state=state or {"icmp_gw": True}, attributions=attrs,
                  network=network_key(cur))
    return run_all(prev, cur, ctx)


class TestDisconnect(unittest.TestCase):
    def test_disconnect_produces_both_axes(self):
        """한 번의 끊김이 품질 판정과 보안 판정을 각각 낸다."""
        prev = obs(vpn=vpn_state("connected"), security="WPA2_PSK")
        cur = obs(vpn=vpn_state("disconnected"), security="WPA2_PSK")
        f = judge(prev, cur)
        self.assertIn("VPN_DISCONNECTED", kinds(f))
        self.assertIn("VPN_PROTECTION_LOST", kinds(f))
        self.assertEqual({x.axis for x in f if x.kind.startswith("VPN_")},
                         {"quality", "security"})

    def test_healthy_first_hop_points_at_the_tunnel(self):
        prev = obs(vpn=vpn_state("connected"), icmp_ok=True)
        cur = obs(vpn=vpn_state("disconnected"), icmp_ok=True)
        f = by_kind(judge(prev, cur), "VPN_DISCONNECTED")
        self.assertIn(msg.WHY_TUNNEL, f.summary)
        self.assertIs(f.evidence["first_hop_alive"], True)

    def test_dead_first_hop_points_at_the_link(self):
        prev = obs(vpn=vpn_state("connected"), icmp_ok=True, gw_mac=GW_MAC)
        cur = obs(vpn=vpn_state("disconnected"), icmp_ok=False, gw_mac=None)
        f = by_kind(judge(prev, cur), "VPN_DISCONNECTED")
        self.assertIn(msg.WHY_LINK, f.summary)
        self.assertIs(f.evidence["first_hop_alive"], False)

    def test_manual_disconnect_is_attributed_not_alarmed(self):
        prev = obs(vpn=vpn_state("connected"))
        cur = obs(vpn=vpn_state("disconnected", reason="Manual_Disconnection"))
        f = by_kind(judge(prev, cur), "VPN_DISCONNECTED")
        self.assertEqual(f.attribution, "user_action")
        self.assertEqual(f.severity, "info")

    def test_manual_disconnect_still_records_that_protection_is_gone(self):
        """직접 끊었어도 '지금 보호받지 않는다'는 사실은 남는다."""
        prev = obs(vpn=vpn_state("connected"), security="WPA2_PSK")
        cur = obs(vpn=vpn_state("disconnected", reason="Manual_Disconnection"),
                  security="WPA2_PSK")
        f = by_kind(judge(prev, cur), "VPN_PROTECTION_LOST")
        self.assertIsNotNone(f)
        self.assertEqual(f.attribution, "user_action")

    def test_sleep_attributes_quality_but_protection_loss_stands(self):
        prev = obs(ts="2026-01-01T00:00:00Z", vpn=vpn_state("connected"))
        cur = obs(ts="2026-01-01T02:00:00Z", vpn=vpn_state("disconnected"))
        f = judge(prev, cur, elapsed=7200.0)
        self.assertEqual(by_kind(f, "VPN_DISCONNECTED").attribution, "sleep")
        self.assertIsNone(by_kind(f, "VPN_PROTECTION_LOST").attribution)

    def test_open_network_raises_protection_loss(self):
        prev = obs(vpn=vpn_state("connected"), security="NONE")
        cur = obs(vpn=vpn_state("disconnected"), security="NONE")
        f = by_kind(judge(prev, cur), "VPN_PROTECTION_LOST")
        self.assertEqual(f.severity, "medium")
        self.assertEqual(f.summary, msg.VPN_PROTECTION_LOST % "warp")

    def test_enterprise_network_does_not_claim_exposure(self):
        prev = obs(vpn=vpn_state("connected"), security="WPA2 Enterprise")
        cur = obs(vpn=vpn_state("disconnected"), security="WPA2 Enterprise")
        self.assertIsNone(by_kind(judge(prev, cur), "VPN_PROTECTION_LOST"))

    def test_unknown_security_says_so_instead_of_guessing(self):
        prev = obs(vpn=vpn_state("connected"), iface_kind="ethernet")
        cur = obs(vpn=vpn_state("disconnected"), iface_kind="ethernet")
        f = by_kind(judge(prev, cur), "VPN_PROTECTION_LOST")
        self.assertIsNotNone(f)
        self.assertEqual(f.summary, msg.VPN_PROTECTION_LOST_UNKNOWN % "warp")
        self.assertEqual(f.severity, "low")


class TestReconnect(unittest.TestCase):
    def test_reconnect_reports_when_it_went_down(self):
        prev = obs(vpn=vpn_state("disconnected"))
        cur = obs(vpn=vpn_state("connected"))
        state = {"icmp_gw": True, "vpn_down_since": {"warp": "2026-01-01T00:00:00Z"}}
        f = by_kind(judge(prev, cur, state=state), "VPN_RECONNECTED")
        self.assertIsNotNone(f)
        self.assertEqual(f.evidence["down_since"], "2026-01-01T00:00:00Z")

    def _reconnect(self, state, cur_ts="2026-01-01T00:07:30Z"):
        prev = obs(ts="2026-01-01T00:07:25Z", vpn=vpn_state("disconnected"))
        cur = obs(ts=cur_ts, vpn=vpn_state("connected"))
        return by_kind(judge(prev, cur, state=state), "VPN_RECONNECTED")

    def test_evidence_carries_the_total_and_the_unmeasured_part(self):
        """끊긴 시간에 측정 공백이 섞이면 둘을 함께 적는다."""
        f = self._reconnect({"icmp_gw": True,
                             "vpn_down_since": {"warp": "2026-01-01T00:00:00Z"},
                             "vpn_down_unmeasured": {"warp": 380.0}})
        self.assertEqual(f.evidence["down_since"], "2026-01-01T00:00:00Z")
        self.assertEqual(f.evidence["down_seconds"], 450.0)
        self.assertEqual(f.evidence["unmeasured_seconds"], 380.0)
        self.assertIn("450", f.summary)
        self.assertIn("380", f.summary)
        self.assertEqual(f.summary, msg.VPN_RECONNECTED
                         % ("warp", msg.VPN_SINCE_UNMEASURED % ("00:00:00", 450.0, 380.0)))

    def test_without_a_gap_the_summary_keeps_its_old_shape(self):
        """공백이 없으면 종전 그대로 — 시작 시각만 적는다."""
        f = self._reconnect({"icmp_gw": True,
                             "vpn_down_since": {"warp": "2026-01-01T00:00:00Z"}})
        self.assertEqual(f.evidence["unmeasured_seconds"], 0.0)
        self.assertEqual(f.evidence["down_seconds"], 450.0)
        self.assertEqual(f.summary,
                         msg.VPN_RECONNECTED % ("warp", msg.VPN_SINCE % "00:00:00"))

    def test_values_that_are_not_timestamps_leave_the_bracket_empty(self):
        """상태 파일은 손으로 고칠 수 있고 재시작을 건너뛰어 남는다."""
        cases = [{}, {"warp": None}, {"warp": ""}, {"warp": "x"}, {"warp": 12345},
                 {"warp": -1}, {"warp": ["2026-01-01T00:00:00Z"]}]
        for downs in cases:
            with self.subTest(downs=downs):
                f = self._reconnect({"icmp_gw": True, "vpn_down_since": downs,
                                     "vpn_down_unmeasured": {"warp": 380.0}})
                self.assertIsNotNone(f)
                self.assertIsNone(f.evidence["down_seconds"])
                self.assertEqual(f.evidence["unmeasured_seconds"], 0.0)
                self.assertEqual(f.summary, msg.VPN_RECONNECTED % ("warp", ""))

    def test_a_start_in_the_future_still_reports_the_time_itself(self):
        """시계가 뒤로 점프해도 종전에 나오던 시작 시각 표기는 남는다.

        끊긴 시간만 계산하지 않는다 — 음수를 적을 수는 없기 때문이다.
        """
        f = self._reconnect({"icmp_gw": True,
                             "vpn_down_since": {"warp": "2026-01-01T09:00:00Z"},
                             "vpn_down_unmeasured": {"warp": 380.0}})
        self.assertIsNone(f.evidence["down_seconds"])
        self.assertEqual(f.evidence["unmeasured_seconds"], 0.0)
        self.assertEqual(f.summary,
                         msg.VPN_RECONNECTED % ("warp", msg.VPN_SINCE % "09:00:00"))

    def test_a_record_kept_from_an_unjudged_cycle_is_read(self):
        """링크 없는 주기에 공급자가 올라오면 기록이 보관분으로 옮겨진다."""
        f = self._reconnect({"icmp_gw": True, "vpn_down_since": {},
                             "vpn_down_pending":
                                 {"warp": {"since": "2026-01-01T00:00:00Z",
                                           "unmeasured": 120.0}}})
        self.assertEqual(f.evidence["down_since"], "2026-01-01T00:00:00Z")
        self.assertEqual(f.evidence["down_seconds"], 450.0)
        self.assertEqual(f.evidence["unmeasured_seconds"], 120.0)

    def test_a_broken_pending_record_is_ignored(self):
        for pending in ({"warp": "x"}, {"warp": {}}, {"warp": {"since": 3}},
                        "x", None):
            with self.subTest(pending=pending):
                f = self._reconnect({"icmp_gw": True, "vpn_down_since": {},
                                     "vpn_down_pending": pending})
                self.assertIsNotNone(f)
                self.assertIsNone(f.evidence["down_seconds"])
                self.assertEqual(f.evidence["unmeasured_seconds"], 0.0)

    def test_broken_unmeasured_values_are_ignored_not_printed(self):
        cases = [None, "x", -5, float("nan"), float("inf"), {"nested": 1}]
        for bad in cases:
            with self.subTest(unmeasured=bad):
                f = self._reconnect({"icmp_gw": True,
                                     "vpn_down_since": {"warp": "2026-01-01T00:00:00Z"},
                                     "vpn_down_unmeasured": {"warp": bad}})
                self.assertEqual(f.evidence["unmeasured_seconds"], 0.0)
                self.assertEqual(f.summary,
                                 msg.VPN_RECONNECTED % ("warp", msg.VPN_SINCE % "00:00:00"))

    def test_unmeasured_never_exceeds_the_total(self):
        """셈이 어긋나도 "끊긴 시간보다 오래 비어 있었다" 고 적지 않는다."""
        f = self._reconnect({"icmp_gw": True,
                             "vpn_down_since": {"warp": "2026-01-01T00:00:00Z"},
                             "vpn_down_unmeasured": {"warp": 99999.0}})
        self.assertEqual(f.evidence["unmeasured_seconds"], 450.0)
        self.assertEqual(f.evidence["down_seconds"], 450.0)

    def test_a_broken_state_shape_does_not_raise(self):
        for state in ({"icmp_gw": True, "vpn_down_since": "x",
                       "vpn_down_unmeasured": "y"},
                      {"icmp_gw": True, "vpn_down_since": None}):
            with self.subTest(state=state):
                f = self._reconnect(state)
                self.assertIsNotNone(f)
                self.assertIsNone(f.evidence["down_since"])
                self.assertEqual(f.evidence["unmeasured_seconds"], 0.0)


class TestNoise(unittest.TestCase):
    def test_unchanged_state_is_silent(self):
        prev = obs(vpn=vpn_state("connected"))
        cur = obs(vpn=vpn_state("connected"))
        self.assertEqual([k for k in kinds(judge(prev, cur)) if k.startswith("VPN")], [])

    def test_unknown_is_not_treated_as_a_disconnect(self):
        """조회 실패를 끊김으로 세면 매번 거짓 경보가 난다."""
        prev = obs(vpn=vpn_state("connected"))
        cur = obs(vpn=vpn_state("unknown", reason="조회 실패"))
        f = judge(prev, cur)
        self.assertIn("VPN_STATE_UNKNOWN", kinds(f))
        self.assertNotIn("VPN_DISCONNECTED", kinds(f))
        self.assertNotIn("VPN_PROTECTION_LOST", kinds(f))

    def test_no_vpn_block_means_no_findings(self):
        self.assertEqual([k for k in kinds(judge(obs(), obs())) if k.startswith("VPN")], [])


class TestProviderDedup(unittest.TestCase):
    def test_third_party_extensions_are_not_double_counted(self):
        """서드파티 VPN 은 scutil --nc list 에도 나타난다. 전용 공급자가 이미 본다."""
        from netmon.vpn import HANDLED_BUNDLES, parse_nc_list

        text = ('Available network connection services in the current set (*=enabled):\n'
                '* (Connected)      00000000-0000-0000-0000-000000000001 '
                'VPN (io.tailscale.ipn.macsys) "Example"  [VPN:io.tailscale.ipn.macsys]\n'
                '* (Disconnected)   00000000-0000-0000-0000-000000000002 '
                'IPSec "Work"  [IPSec]\n')
        rows = parse_nc_list(text)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["bundle"], "io.tailscale.ipn.macsys")
        self.assertEqual(rows[0]["state"], "connected")
        self.assertTrue(rows[0]["enabled"])
        self.assertEqual(rows[1]["bundle"], "IPSec")
        remaining = [r for r in rows if r["bundle"] not in HANDLED_BUNDLES]
        self.assertEqual(len(remaining), 1)

    def test_service_names_are_not_read(self):
        from netmon.vpn import parse_nc_list

        text = ('* (Connected) 00000000-0000-0000-0000-000000000003 '
                'IPSec "회사이름-VPN"  [IPSec]\n')
        row = parse_nc_list(text)[0]
        self.assertNotIn("회사이름", repr(row))




class TestWarpModeParsing(unittest.TestCase):
    """모드 문자열은 요약문에 그대로 실린다. 엉뚱한 줄을 집으면 공개 보고서에
    외부 문자열이 들어간다."""

    SETTINGS = (
        "Merged configuration:\n"
        "(not set)\tCompliance Environment: Normal\n"
        "(default)\tAlways On: false\n"
        "(user set)\tMode: DnsOverTls\n"
        "(default)\tWARP tunnel protocol: MASQUE\n"
        "(not set)\tMASQUE Protocol Settings: \n"
        "  HTTP Version: MASQUE (HTTP/3 with HTTP/2 fallback)\n"
    )

    def test_it_reads_the_mode_line(self):
        self.assertEqual(vpnmod.parse_warp_mode(self.SETTINGS), "DnsOverTls")

    def test_it_ignores_other_lines_that_mention_mode(self):
        text = ("(network policy)\tWARP tunnel protocol: MASQUE\n"
                "(user set)\tExclude mode, with hosts/ips:\n"
                "(user set)\tMode: WarpWithDnsOverHttps\n")
        self.assertEqual(vpnmod.parse_warp_mode(text), "WarpWithDnsOverHttps")

    def test_an_unexpected_value_is_not_taken(self):
        self.assertIsNone(vpnmod.parse_warp_mode("(user set)\tMode: 10.0.0.0/8\n"))
        self.assertIsNone(vpnmod.parse_warp_mode("(user set)\tMode: \n"))
        self.assertIsNone(vpnmod.parse_warp_mode(""))

    def test_mode_names_map_to_whether_there_is_a_tunnel(self):
        for name, expect in (("DnsOverTls", False), ("DnsOverHttps", False),
                             ("WarpWithDnsOverHttps", True), ("Warp", True),
                             ("Proxy", None), (None, None), ("", None)):
            self.assertIs(vpnmod.warp_tunnel_for(name), expect, name)

    def test_a_failed_lookup_keeps_the_last_known_mode(self):
        w = vpnmod.Warp()
        calls = []

        def fake_run(argv, timeout=None, stdin=""):
            calls.append(argv)
            from netmon.util import CmdResult
            if len(calls) == 1:
                return CmdResult(argv, 0, self.SETTINGS, "")
            return CmdResult(argv, 1, "", "daemon busy")

        orig = vpnmod.run
        vpnmod.run = fake_run
        try:
            self.assertEqual(w.mode(now=0.0), "DnsOverTls")
            self.assertEqual(w.mode(now=100.0), "DnsOverTls")  # 조회 실패, 아직 유효
            self.assertIsNone(w.mode(now=1000.0))  # 너무 오래됐으면 버린다
        finally:
            vpnmod.run = orig
        self.assertEqual(len(calls), 3)

    def test_an_unreadable_output_does_not_retry_every_cycle(self):
        """해석 못 하는 출력에서도 간격은 지켜야 한다. 기능이 조용히 꺼진 바로
        그 상태에서만 비용 제한이 사라지면 안 된다."""
        w = vpnmod.Warp()
        calls = []

        def fake_run(argv, timeout=None, stdin=""):
            from netmon.util import CmdResult
            calls.append(argv)
            return CmdResult(argv, 0, "Merged configuration:\n(default)\tAlways On: false\n", "")

        orig = vpnmod.run
        vpnmod.run = fake_run
        try:
            for t in (0.0, 5.0, 10.0, 55.0):
                self.assertIsNone(w.mode(now=t))
            self.assertEqual(len(calls), 1)
        finally:
            vpnmod.run = orig

    def test_it_does_not_ask_every_cycle(self):
        w = vpnmod.Warp()
        calls = []

        def fake_run(argv, timeout=None, stdin=""):
            from netmon.util import CmdResult
            calls.append(argv)
            return CmdResult(argv, 0, self.SETTINGS, "")

        orig = vpnmod.run
        vpnmod.run = fake_run
        try:
            for t in (0.0, 5.0, 10.0, 55.0):
                w.mode(now=t)
            self.assertEqual(len(calls), 1)
            w.mode(now=61.0)
            self.assertEqual(len(calls), 2)
        finally:
            vpnmod.run = orig


class TestConnectedButNoTunnel(unittest.TestCase):
    """2026-09-21 실측: DNS only 모드에서도 warp-cli 는 "Connected" 를 돌려준다.
    끊긴 적이 없으니 상태 전환 판정에 걸리지 않아, 보호가 사라진 채로 조용했다."""

    def _pair(self, before, after, security="WPA2_PSK", **kw):
        prev = obs(vpn=before, security=security)
        cur = obs(ts="2026-01-01T00:00:05Z", vpn=after, security=security, **kw)
        return judge(prev, cur)

    def test_switching_to_a_dns_only_mode_is_reported(self):
        found = self._pair(vpn_state(mode="WarpWithDnsOverHttps", tunnel=True),
                           vpn_state(mode="DnsOverTls", tunnel=False))
        f = by_kind(found, "VPN_TUNNEL_OFF")
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, "medium")
        self.assertIn("DnsOverTls", f.summary)
        self.assertTrue(f.evidence["passively_readable"])

    def test_it_does_not_repeat_every_cycle(self):
        found = self._pair(vpn_state(mode="DnsOverTls", tunnel=False),
                           vpn_state(mode="DnsOverTls", tunnel=False))
        self.assertIsNone(by_kind(found, "VPN_TUNNEL_OFF"))

    def test_joining_another_network_while_off_reports_again(self):
        found = self._pair(vpn_state(mode="DnsOverTls", tunnel=False),
                           vpn_state(mode="DnsOverTls", tunnel=False),
                           ssid="OtherNet", gateway="198.51.100.1",
                           gw_mac="00:00:5e:00:53:2a")
        self.assertIsNotNone(by_kind(found, "VPN_TUNNEL_OFF"))

    def test_an_sae_network_is_not_called_passively_readable(self):
        found = self._pair(vpn_state(mode="WarpWithDnsOverHttps", tunnel=True),
                           vpn_state(mode="DnsOverTls", tunnel=False),
                           security="WPA3_SAE")
        f = by_kind(found, "VPN_TUNNEL_OFF")
        self.assertEqual(f.severity, "low")
        self.assertFalse(f.evidence["passively_readable"])

    def test_an_unknown_mode_is_not_called_unprotected(self):
        found = self._pair(vpn_state(mode="WarpWithDnsOverHttps", tunnel=True),
                           vpn_state(mode="Proxy", tunnel=None))
        self.assertIsNone(by_kind(found, "VPN_TUNNEL_OFF"))

    def test_coming_back_to_a_tunnelling_mode_is_logged(self):
        found = self._pair(vpn_state(mode="DnsOverTls", tunnel=False),
                           vpn_state(mode="WarpWithDnsOverHttps", tunnel=True))
        f = by_kind(found, "VPN_TUNNEL_ON")
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, "info")

    def test_a_failed_mode_lookup_does_not_repeat_the_warning(self):
        """조회 실패로 tunnel 이 None 이 되었다가 돌아와도 다시 알리지 않는다."""
        st = {"icmp_gw": True}
        a = obs(vpn=vpn_state(mode="WarpWithDnsOverHttps", tunnel=True), security="WPA2_PSK")
        b = obs(ts="2026-01-01T00:00:05Z", vpn=vpn_state(mode="DnsOverTls", tunnel=False),
                security="WPA2_PSK")
        c = obs(ts="2026-01-01T00:00:10Z", vpn=vpn_state(mode=None, tunnel=None),
                security="WPA2_PSK")
        d = obs(ts="2026-01-01T00:00:15Z", vpn=vpn_state(mode="DnsOverTls", tunnel=False),
                security="WPA2_PSK")
        self.assertIsNotNone(by_kind(judge(a, b, st), "VPN_TUNNEL_OFF"))
        judge(b, c, st)
        self.assertIsNone(by_kind(judge(c, d, st), "VPN_TUNNEL_OFF"))

    def test_moving_without_an_ssid_still_reports(self):
        """SSID 를 못 읽는 기계에서는 다른 장소가 link_restart 로만 나타난다."""
        prev = obs(vpn=vpn_state(mode="DnsOverTls", tunnel=False), security="WPA2_PSK",
                   ssid=None)
        cur = obs(ts="2026-01-01T00:00:05Z", vpn=vpn_state(mode="DnsOverTls", tunnel=False),
                  security="WPA2_PSK", ssid=None)
        attrs = ["link_restart"]
        ctx = Context(elapsed=5.0, interval=5.0, features=ON, state={"icmp_gw": True},
                      attributions=attrs, network=network_key(cur))
        self.assertIsNotNone(by_kind(run_all(prev, cur, ctx), "VPN_TUNNEL_OFF"))

    def test_old_samples_without_the_field_say_nothing(self):
        found = self._pair(vpn_state(), vpn_state())
        self.assertIsNone(by_kind(found, "VPN_TUNNEL_OFF"))
        self.assertIsNone(by_kind(found, "VPN_TUNNEL_ON"))


if __name__ == "__main__":
    unittest.main()
