"""실측 로그를 읽다가 드러난 결함들.

전부 상시 실행 기록에서 실제로 나온 일이다. 합성 입력만으로는 보이지 않았다.
"""
from __future__ import annotations

import unittest

from netmon import baseline
from netmon.collect.arp import normalize_mac, parse_arp_table
from netmon.detect import Context, attributions_for, network_key, run_all
from tests.helpers import (BSSID, BSSID_ALT, GW_MAC, GW_MAC_ALT, SSID,
                           by_kind, kinds, obs, vpn_state)

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


class TestVpnDropConsequences(unittest.TestCase):
    """2026-09-16 05:56:48 의 WARP 끊김 49초.

    WARP 가 내려가자 리졸버가 DHCP 가 준 DNS 로 돌아가고 기본 경로가 3개에서
    2개가 됐다. 둘 다 끊김의 **결과**인데 독립된 보안 사건(high)으로 올라갔고,
    그 때문에 엉뚱한 조사까지 열렸다.
    """

    OFFERED = ("192.0.2.53", "198.51.100.53")
    LOOPBACK = ("127.0.2.2", "127.0.2.3")

    def _up(self, ts):
        return obs(ts=ts, vpn=vpn_state("connected"), resolvers=self.LOOPBACK,
                   via_loopback=True, dns=self.OFFERED)

    def _down(self, ts):
        return obs(ts=ts, vpn=vpn_state("connecting"), resolvers=self.OFFERED,
                   via_loopback=False, dns=self.OFFERED)

    def test_resolver_change_is_attributed_to_the_vpn_drop(self):
        f = by_kind(judge(self._up("2026-01-01T00:00:00Z"),
                          self._down("2026-01-01T00:00:05Z")), "RESOLVER_CHANGED")
        self.assertIsNotNone(f)
        self.assertEqual(f.attribution, "vpn_change")
        self.assertEqual(f.severity, "low", "끊김의 결과를 high 로 올리면 안 된다")

    def test_the_drop_itself_is_still_reported(self):
        found = judge(self._up("2026-01-01T00:00:00Z"), self._down("2026-01-01T00:00:05Z"))
        self.assertIn("VPN_DISCONNECTED", kinds(found))
        self.assertIn("VPN_PROTECTION_LOST", kinds(found))
        self.assertIsNone(by_kind(found, "VPN_PROTECTION_LOST").attribution,
                          "보호가 사라진 사실까지 억제하면 안 된다")

    def test_a_resolver_change_to_a_third_party_is_not_attributed(self):
        """공격자가 VPN 을 끊으면서 리졸버를 자기 것으로 바꿀 수 있다.

        DHCP 가 준 값도 루프백도 아니면 VPN 전환으로 설명되지 않는다.
        """
        cur = obs(ts="2026-01-01T00:00:05Z", vpn=vpn_state("connecting"),
                  resolvers=("192.0.2.99",), via_loopback=False, dns=self.OFFERED)
        f = by_kind(judge(self._up("2026-01-01T00:00:00Z"), cur), "RESOLVER_CHANGED")
        self.assertIsNone(f.attribution)
        self.assertEqual(f.severity, "high")

    def test_tunnel_route_change_is_attributed_but_physical_is_not(self):
        up = obs(ts="2026-01-01T00:00:00Z", vpn=vpn_state("connected"))
        up.data["route"]["default4"] = [
            {"gateway": {"id": "ipv4", "v": "192.0.2.1"}, "iface": "en0", "flags": "UGScg"},
            {"gateway": "link#26", "iface": "utun6", "flags": "UCSIg"}]
        down = obs(ts="2026-01-01T00:00:05Z", vpn=vpn_state("connecting"))
        down.data["route"]["default4"] = [
            {"gateway": {"id": "ipv4", "v": "192.0.2.1"}, "iface": "en0", "flags": "UGScg"}]
        f = by_kind(judge(up, down), "DEFAULT_ROUTE_CHANGED")
        self.assertEqual(f.attribution, "vpn_change")

        moved = obs(ts="2026-01-01T00:00:05Z", vpn=vpn_state("connecting"))
        moved.data["route"]["default4"] = [
            {"gateway": {"id": "ipv4", "v": "192.0.2.77"}, "iface": "en0", "flags": "UGScg"},
            {"gateway": "link#26", "iface": "utun6", "flags": "UCSIg"}]
        g = by_kind(judge(up, moved), "DEFAULT_ROUTE_CHANGED")
        self.assertIsNone(g.attribution, "물리 경로가 바뀐 것은 VPN 으로 설명되지 않는다")


class TestSingleVpnDropConcludes(unittest.TestCase):
    """49초짜리 끊김 하나로 열린 조사가 120주기를 다 쓰고 "판별 실패" 로 끝났다."""

    def test_one_drop_then_quiet_concludes_without_burning_the_budget(self):
        from netmon import investigate
        from netmon import messages as msg
        from netmon.investigate.playbooks import VpnDrop

        state = {"icmp_gw": True}
        inv = investigate.Investigator({})
        prev = obs(ts="2026-01-01T00:00:00Z", vpn=vpn_state("connected"), icmp_ok=True)
        seq = [obs(ts="2026-01-01T00:00:05Z", vpn=vpn_state("disconnected"), icmp_ok=True),
               obs(ts="2026-01-01T00:00:10Z", vpn=vpn_state("connected"), icmp_ok=True)]
        seq += [obs(ts="2026-01-01T00:%02d:%02dZ" % ((i // 12) + 1, (i * 5) % 60),
                    vpn=vpn_state("connected"), icmp_ok=True)
                for i in range(VpnDrop.SETTLED_CYCLES + 2)]
        for cur in seq:
            ctx = Context(elapsed=5.0, interval=5.0, features=ON, state=state,
                          attributions=attributions_for(prev, cur, 5.0, 5.0),
                          network=network_key(cur))
            found = run_all(prev, cur, ctx)
            inv.run(prev, cur, ctx, found, state)
            prev = cur
        done = [i for i in investigate.Investigator.load(state)
                if i.kind == "vpn_drop" and not i.open]
        self.assertTrue(done, "한 번 끊겼다 복구된 것도 결론을 내야 한다")
        self.assertEqual(done[0].verdict, msg.INV_VPN_VERDICT_SINGLE)
        self.assertLess(done[0].cycles, VpnDrop.max_cycles,
                        "예산을 다 쓰기 전에 끝나야 한다")


class TestLaggedConsequences(unittest.TestCase):
    """2026-09-16 06:54 의 WARP 재연결.

    실제 관측:
      06:54:01  warp=connecting  리졸버 외부   [VPN 상태 변화]
      06:54:06  warp=connecting  리졸버 루프백 [리졸버만 변화]  ← high 로 올라감
      06:54:10  warp=connected

    WARP 는 connecting 인 채로 리졸버를 설치한다. 상태 전환과 그 결과가 서로
    다른 주기에 떨어지므로, 같은 주기만 보는 억제는 놓친다.
    """

    OFFERED = ("192.0.2.53",)
    LOOPBACK = ("127.0.2.2",)

    def _judge_sequence(self, samples):
        from netmon import baseline
        state = {"icmp_gw": True}
        prev = samples[0]
        out = []
        for cur in samples[1:]:
            attrs = attributions_for(prev, cur, 5.0, 5.0)
            state = baseline.update_counters(state, cur, attrs, 5.0, 5.0)
            ctx = Context(elapsed=5.0, interval=5.0, features=ON, state=state,
                          attributions=attrs, network=network_key(cur))
            out.append(run_all(prev, cur, ctx))
            state = baseline.update_baselines(state, cur, 5.0, 5.0)
            prev = cur
        return out

    def test_resolver_returning_one_cycle_after_the_transition_is_attributed(self):
        seq = [
            obs(ts="2026-01-01T00:00:00Z", vpn=vpn_state("disconnected"),
                resolvers=self.OFFERED, via_loopback=False, dns=self.OFFERED),
            obs(ts="2026-01-01T00:00:05Z", vpn=vpn_state("connecting"),
                resolvers=self.OFFERED, via_loopback=False, dns=self.OFFERED),
            obs(ts="2026-01-01T00:00:10Z", vpn=vpn_state("connecting"),
                resolvers=self.LOOPBACK, via_loopback=True, dns=self.OFFERED),
        ]
        lagged = self._judge_sequence(seq)[-1]
        f = by_kind(lagged, "RESOLVER_CHANGED")
        self.assertIsNotNone(f)
        self.assertIsNotNone(f.attribution,
                             "전환 다음 주기에 온 결과도 설명돼야 한다")
        self.assertEqual(f.severity, "low")

    def test_a_third_party_resolver_in_the_window_is_still_high(self):
        """안정화 창 안이라도 값의 앞뒤가 맞지 않으면 억제하지 않는다."""
        seq = [
            obs(ts="2026-01-01T00:00:00Z", vpn=vpn_state("disconnected"),
                resolvers=self.OFFERED, via_loopback=False, dns=self.OFFERED),
            obs(ts="2026-01-01T00:00:05Z", vpn=vpn_state("connecting"),
                resolvers=self.OFFERED, via_loopback=False, dns=self.OFFERED),
            obs(ts="2026-01-01T00:00:10Z", vpn=vpn_state("connecting"),
                resolvers=("192.0.2.99",), via_loopback=False, dns=self.OFFERED),
        ]
        f = by_kind(self._judge_sequence(seq)[-1], "RESOLVER_CHANGED")
        self.assertIsNone(f.attribution)
        self.assertEqual(f.severity, "high")

    def test_the_window_closes(self):
        """창이 영원히 열려 있으면 그 뒤의 진짜 변조도 묻힌다."""
        from netmon import baseline
        state = baseline.update_counters({}, obs(), ["vpn_change"], 5.0, 5.0)
        self.assertTrue(state.get("settle_left_s"))
        for _ in range(int(baseline.SETTLE_SECONDS / 5) + 1):
            state = baseline.update_counters(state, obs(), [], 5.0, 5.0)
        self.assertIsNone(state.get("settle_left_s"))


class TestSecurityKnownFromTheCycleBefore(unittest.TestCase):
    """잠에서 깬 직후 Wi-Fi 가 아직 붙지 않아 "신뢰 여부 판단 불가" 가 나왔다.

    직전 주기에는 WPA2_PSK 인 것을 알고 있었다.
    """

    def test_falls_back_to_the_last_known_security_on_the_same_interface(self):
        prev = obs(ts="2026-01-01T00:00:00Z", vpn=vpn_state("connected"),
                   security="WPA2_PSK")
        cur = obs(ts="2026-01-01T00:00:05Z", vpn=vpn_state("disconnected"),
                  iface_kind="wifi")
        cur.data["wifi"] = {"applicable": False, "reason": "아직 미접속"}
        f = by_kind(judge(prev, cur), "VPN_PROTECTION_LOST")
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, "medium")
        self.assertNotIn("판단 불가", f.summary)

    def test_a_different_interface_does_not_inherit(self):
        prev = obs(ts="2026-01-01T00:00:00Z", vpn=vpn_state("connected"),
                   security="WPA2_PSK", iface="en0")
        cur = obs(ts="2026-01-01T00:00:05Z", vpn=vpn_state("disconnected"),
                  iface="en1", iface_kind="ethernet")
        f = by_kind(judge(prev, cur), "VPN_PROTECTION_LOST")
        self.assertIn("판단 불가", f.summary)


class TestSamePrivateRangeDifferentPlace(unittest.TestCase):
    """같은 사설 대역을 쓰는 다른 장소를 구분하지 못하던 구멍.

    맥북과 맥미니가 물리적으로 멀리 있는데 둘 다 192.168.x.1 을 게이트웨이로
    쓰고 있었다. network_key 는 (인터페이스, SSID, 서브넷)인데 위치 권한이
    없으면 SSID 가 비어서 사실상 (인터페이스, 서브넷)만 남는다. 집과 카페가
    같은 대역이면 도구는 이동을 알아채지 못하고, 당연히 바뀌는 게이트웨이
    MAC 이 high 로 뜬다.

    링크 재시작을 근거로 쓴다. 경로에 끼어든 공격자는 내 링크를 내렸다
    올리지 않는다.
    """

    def _move(self, **cur_kw):
        """같은 서브넷·다른 장소로 이동 (링크가 끊겼다 붙음, IP 도 바뀜)."""
        prev = obs(ts="2026-01-01T00:00:00Z", gw_mac=GW_MAC, my_ip="192.0.2.50",
                   lease_start="2026-01-01 00:00:00", ssid=None, bssid=None)
        base = dict(gw_mac=GW_MAC_ALT, my_ip="192.0.2.77",
                    lease_start="2026-01-01 00:10:00", ssid=None, bssid=None)
        base.update(cur_kw)
        cur = obs(ts="2026-01-01T00:00:05Z", **base)
        return prev, cur

    def test_moving_to_a_same_subnet_place_is_recognised(self):
        prev, cur = self._move()
        attrs = attributions_for(prev, cur, 5.0, 5.0)
        self.assertIn("link_restart", attrs,
                      "임대가 새로 시작되고 IP 도 바뀌면 이동으로 봐야 한다")

    def test_the_mac_change_after_moving_is_not_high(self):
        prev, cur = self._move()
        f = by_kind(judge(prev, cur), "GW_MAC_CHANGED")
        self.assertIsNotNone(f, "판정 자체는 남아야 한다")
        self.assertEqual(f.attribution, "link_restart")
        self.assertEqual(f.severity, "low")

    def test_a_mac_change_without_a_link_restart_is_still_high(self):
        """링크가 멀쩡한데 MAC 만 바뀌는 것이 스푸핑의 모양이다."""
        prev = obs(ts="2026-01-01T00:00:00Z", gw_mac=GW_MAC, ssid=None, bssid=None)
        cur = obs(ts="2026-01-01T00:00:05Z", gw_mac=GW_MAC_ALT, ssid=None, bssid=None)
        f = by_kind(judge(prev, cur), "GW_MAC_CHANGED")
        self.assertIsNone(f.attribution)
        self.assertEqual(f.severity, "high")

    def test_a_dhcp_renewal_alone_is_not_a_move(self):
        """갱신은 IP 를 유지한다. 그것만으로 이동이라고 보면 억제가 헐거워진다."""
        prev = obs(ts="2026-01-01T00:00:00Z", my_ip="192.0.2.50",
                   lease_start="2026-01-01 00:00:00", ssid=None, bssid=None)
        cur = obs(ts="2026-01-01T00:00:05Z", my_ip="192.0.2.50",
                  lease_start="2026-01-01 01:00:00", ssid=None, bssid=None)
        self.assertNotIn("link_restart", attributions_for(prev, cur, 5.0, 5.0))

    def test_a_known_ssid_still_decides_on_its_own(self):
        """SSID 를 읽을 수 있으면 링크 재시작을 근거로 쓰지 않는다.

        같은 SSID 로 다시 붙었는데 게이트웨이 MAC 이 바뀌었다면 그것이야말로
        evil twin 의 모양이다. 링크 재시작으로 억제하면 그 경우를 덮는다.
        """
        prev = obs(ts="2026-01-01T00:00:00Z", gw_mac=GW_MAC, ssid=SSID, bssid=BSSID,
                   my_ip="192.0.2.50", lease_start="2026-01-01 00:00:00")
        cur = obs(ts="2026-01-01T00:00:05Z", gw_mac=GW_MAC_ALT, ssid=SSID, bssid=BSSID_ALT,
                  my_ip="192.0.2.77", lease_start="2026-01-01 00:10:00")
        attrs = attributions_for(prev, cur, 5.0, 5.0)
        self.assertNotIn("link_restart", attrs)
        f = by_kind(judge(prev, cur), "GW_MAC_CHANGED")
        self.assertIsNone(f.attribution, "같은 SSID 의 MAC 변경은 덮이면 안 된다")
        self.assertEqual(f.severity, "high")

    def test_moving_to_a_different_ssid_uses_the_ssid_not_the_link(self):
        prev = obs(ts="2026-01-01T00:00:00Z", gw_mac=GW_MAC, ssid=SSID, bssid=BSSID)
        cur = obs(ts="2026-01-01T00:00:05Z", gw_mac=GW_MAC_ALT, ssid="OtherNet",
                  bssid=BSSID_ALT)
        attrs = attributions_for(prev, cur, 5.0, 5.0)
        self.assertIn("network_change", attrs)
        self.assertNotIn("link_restart", attrs)

    def test_baselines_are_dropped_on_a_link_restart(self):
        """이전 장소의 정상값을 새 장소에 적용하면 첫 몇 분이 통째로 오탐이 된다."""
        from netmon import baseline
        state = {"rtt_ewma": 40.0, "arp_reply_rate": 5.0, "icmp_gw": True}
        fresh = baseline.reset_for_new_network(state)
        self.assertIsNone(fresh.get("rtt_ewma"))
        self.assertIsNone(fresh.get("arp_reply_rate"))
        self.assertIsNone(fresh.get("icmp_gw"))


class TestInterfaceVanishIsNotAnInterfaceChange(unittest.TestCase):
    """실측: 링크가 끊기면 주 인터페이스가 None 이 되고 다시 붙으면 en0 로 돌아온다.

      07:02:35  primary=None
      07:02:45  primary=en0

    이것을 iface_change 로 읽으면 SSID 검사를 건너뛰고 무조건 억제하게 되어,
    같은 SSID 로 다시 붙었는데 게이트웨이가 바뀐 경우 — evil twin 의 모양 —
    까지 덮는다. 오늘 억제된 보안 판정 22건 중 18건이 이 경로였다.
    """

    def _vanish_return(self, ssid=None, bssid=None, gw_mac=GW_MAC_ALT):
        gone = obs(ts="2026-01-01T00:00:00Z", gateway=None, gw_mac=None,
                   ssid=ssid, bssid=bssid)
        gone.data["iface"]["primary"] = None
        gone.data["iface"]["primary_kind"] = "unknown"
        gone.data["iface"]["default4_iface"] = None
        back = obs(ts="2026-01-01T00:00:05Z", gw_mac=gw_mac, ssid=ssid, bssid=bssid)
        return gone, back

    def test_vanishing_and_returning_is_not_an_interface_change(self):
        gone, back = self._vanish_return()
        self.assertNotIn("iface_change", attributions_for(gone, back, 5.0, 5.0))

    def test_it_counts_as_a_link_restart_when_the_ssid_is_unknown(self):
        """정체성은 주 인터페이스가 있던 마지막 관측(anchor)과 비교한다."""
        gone, back = self._vanish_return()
        anchor = obs(ts="2025-12-31T23:59:55Z", gw_mac=GW_MAC)
        attrs = attributions_for(gone, back, 5.0, 5.0, anchor=anchor)
        self.assertIn("link_restart", attrs)
        self.assertNotIn("iface_change", attrs)
        self.assertNotIn("network_change", attrs)

    def test_a_same_ssid_gateway_change_survives_the_reconnect(self):
        """같은 SSID 로 다시 붙었는데 게이트웨이 MAC 이 바뀌었다 — 덮이면 안 된다."""
        gone, back = self._vanish_return(ssid=SSID, bssid=BSSID_ALT)
        anchor = obs(ts="2025-12-31T23:59:55Z", gw_mac=GW_MAC, ssid=SSID, bssid=BSSID)
        attrs = attributions_for(gone, back, 5.0, 5.0, anchor=anchor)
        self.assertNotIn("iface_change", attrs)
        self.assertNotIn("link_restart", attrs)
        self.assertNotIn("network_change", attrs)

    def test_a_real_move_across_a_link_drop_is_still_seen(self):
        """링크가 끊겼다 다른 SSID 로 붙으면 이동으로 알아봐야 한다."""
        gone, back = self._vanish_return(ssid="OtherNet", bssid=BSSID_ALT)
        anchor = obs(ts="2025-12-31T23:59:55Z", gw_mac=GW_MAC, ssid=SSID, bssid=BSSID)
        self.assertIn("network_change", attributions_for(gone, back, 5.0, 5.0, anchor=anchor))

    def test_a_real_interface_switch_is_still_an_interface_change(self):
        prev = obs(ts="2026-01-01T00:00:00Z", iface="en0", iface_kind="wifi")
        cur = obs(ts="2026-01-01T00:00:05Z", iface="en1", iface_kind="ethernet")
        self.assertIn("iface_change", attributions_for(prev, cur, 5.0, 5.0))


class TestRouteReappearingAfterLinkReturn(unittest.TestCase):
    """링크가 돌아오면서 물리 기본 경로가 다시 생기는 것은 그 복구의 결과다.

    실측 07:02:45 에서 high 로 올라가 엉뚱한 조사까지 열었다.
    """

    def _routes(self, o, entries):
        o.data["route"]["default4"] = [
            {"gateway": ({"id": "ipv4", "v": gw} if not gw.startswith("link#") else gw),
             "iface": iface, "flags": "UGScg"} for gw, iface in entries]
        o.data["route"]["default4_count"] = len(entries)
        return o

    def _ctx(self, prev, cur, settling="link_restart"):
        state = {"icmp_gw": True, "settle_left_s": 30.0, "settle_reason": settling}
        return Context(elapsed=5.0, interval=5.0, features=ON, state=state,
                       attributions=[], network=network_key(cur))

    def test_physical_route_appearing_is_attributed(self):
        prev = self._routes(obs(ts="2026-01-01T00:00:00Z"), [("link#26", "utun6")])
        cur = self._routes(obs(ts="2026-01-01T00:00:05Z"),
                           [("192.0.2.1", "en0"), ("link#26", "utun6")])
        f = by_kind(run_all(prev, cur, self._ctx(prev, cur)), "DEFAULT_ROUTE_CHANGED")
        self.assertIsNotNone(f)
        self.assertEqual(f.attribution, "link_restart")
        self.assertEqual(f.severity, "low")

    def test_physical_route_switching_gateway_is_not_attributed(self):
        """있던 물리 경로가 다른 게이트웨이로 바뀌는 것이 가로채기의 모양이다."""
        prev = self._routes(obs(ts="2026-01-01T00:00:00Z"), [("192.0.2.1", "en0")])
        cur = self._routes(obs(ts="2026-01-01T00:00:05Z"), [("192.0.2.99", "en0")])
        f = by_kind(run_all(prev, cur, self._ctx(prev, cur)), "DEFAULT_ROUTE_CHANGED")
        self.assertIsNone(f.attribution, "안정화 창 안이라도 덮이면 안 된다")
        self.assertEqual(f.severity, "high")
