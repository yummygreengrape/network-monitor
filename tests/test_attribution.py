"""억제 규칙 — 이 도구에서 가장 틀리기 쉬운 부분.

원래 스크립트는 끊김 원인을 하나만 골랐고 순서가
SLEEP > NETWORK_CHANGE > ARP_ANOMALY 였다. 그래서 네트워크가 바뀌는 동시에
게이트웨이 MAC 이 바뀌면 — evil twin 으로 유인당하는 바로 그 순간 —
ARP 이상이 기록되지 않았다. 이 파일은 그 회귀를 막는다.
"""
from __future__ import annotations

import unittest

from netmon.detect import Context, attributions_for, network_key, run_all
from tests.helpers import (DHCP_SRV, DHCP_SRV2, GW, GW2, GW2_MAC, GW_MAC,
                           GW_MAC_ALT, SSID, by_kind, kinds, obs, vpn_state)

FEATURES = {"detect.l2": True, "detect.dhcp": True, "detect.dns": True,
            "detect.route": True, "detect.wifi": True, "detect.quality": True}


def judge(prev, cur, elapsed=5.0, interval=5.0, state=None, features=None):
    attrs = attributions_for(prev, cur, elapsed, interval)
    ctx = Context(elapsed=elapsed, interval=interval,
                  features=features or FEATURES, state=state or {},
                  attributions=attrs, network=network_key(cur))
    return run_all(prev, cur, ctx), attrs


class TestNetworkIdentity(unittest.TestCase):
    def test_gateway_mac_is_not_part_of_identity(self):
        """MAC 은 네트워크 정체성에 들어가면 안 된다.

        들어가면 MAC 이 바뀔 때마다 '다른 네트워크로 옮겼다'가 되어
        스스로 경보를 지운다.
        """
        a = obs(gw_mac=GW_MAC)
        b = obs(gw_mac=GW_MAC_ALT)
        self.assertEqual(network_key(a), network_key(b))

    def test_moving_to_another_network_changes_identity(self):
        a = obs(gateway=GW, dhcp_server=DHCP_SRV, my_ip="192.0.2.50")
        b = obs(gateway=GW2, dhcp_server=DHCP_SRV2, gw_mac=GW2_MAC,
                my_ip="198.51.100.50")
        self.assertNotEqual(network_key(a), network_key(b))


class TestMacChangeNotMasked(unittest.TestCase):
    def test_mac_change_on_same_network_is_high(self):
        prev = obs(ts="2026-01-01T00:00:00Z", gw_mac=GW_MAC)
        cur = obs(ts="2026-01-01T00:00:05Z", gw_mac=GW_MAC_ALT)
        findings, attrs = judge(prev, cur)
        f = by_kind(findings, "GW_MAC_CHANGED")
        self.assertIsNotNone(f, "같은 네트워크에서 MAC 이 바뀌면 반드시 판정이 나와야 한다")
        self.assertEqual(f.severity, "high")
        self.assertIsNone(f.attribution)
        self.assertEqual(attrs, [])

    def test_mac_change_during_network_move_is_recorded_but_attributed(self):
        """네트워크 이동으로 설명돼도 판정은 남는다. 심각도만 내려간다."""
        prev = obs(ts="2026-01-01T00:00:00Z", gateway=GW, gw_mac=GW_MAC,
                   dhcp_server=DHCP_SRV, my_ip="192.0.2.50")
        cur = obs(ts="2026-01-01T00:00:05Z", gateway=GW2, gw_mac=GW2_MAC,
                  dhcp_server=DHCP_SRV2, routers=(GW2,), my_ip="198.51.100.50")
        findings, attrs = judge(prev, cur)
        self.assertIn("network_change", attrs)
        f = by_kind(findings, "GW_MAC_CHANGED")
        self.assertIsNotNone(f, "억제는 판정을 지우는 것이 아니다")
        self.assertEqual(f.attribution, "network_change")
        self.assertEqual(f.severity, "low")

    def test_sleep_does_not_suppress_security_findings(self):
        """자는 동안 MAC 이 바뀌는 것이야말로 확인해야 할 일이다.

        원래 스크립트는 SLEEP 을 가장 우선해서 이 경우를 통째로 삼켰다.
        """
        prev = obs(ts="2026-01-01T00:00:00Z", gw_mac=GW_MAC)
        cur = obs(ts="2026-01-01T02:00:00Z", gw_mac=GW_MAC_ALT)
        findings, attrs = judge(prev, cur, elapsed=7200.0)
        self.assertIn("sleep", attrs)
        f = by_kind(findings, "GW_MAC_CHANGED")
        self.assertIsNotNone(f)
        self.assertIsNone(f.attribution, "잠자기는 보안 판정을 설명하지 못한다")
        self.assertEqual(f.severity, "high")

    def test_sleep_does_suppress_quality_findings(self):
        prev = obs(ts="2026-01-01T00:00:00Z")
        cur = obs(ts="2026-01-01T02:00:00Z", lease_start="2026-01-01 02:00:00")
        findings, attrs = judge(prev, cur, elapsed=7200.0)
        f = by_kind(findings, "DHCP_LEASE_RENEWED")
        self.assertIsNotNone(f)
        self.assertEqual(f.attribution, "sleep")


class TestAxesAreIndependent(unittest.TestCase):
    def test_one_cycle_can_produce_both_axes(self):
        """품질 사건이 보안 사건을 가리지 않는다. 둘 다 나와야 한다."""
        prev = obs(ts="2026-01-01T00:00:00Z", gw_mac=GW_MAC,
                   lease_start="2026-01-01 00:00:00")
        cur = obs(ts="2026-01-01T00:00:05Z", gw_mac=GW_MAC_ALT,
                  lease_start="2026-01-01 00:00:04")
        findings, _ = judge(prev, cur)
        axes = {f.axis for f in findings}
        self.assertIn("security", axes)
        self.assertIn("quality", axes)
        self.assertIn("GW_MAC_CHANGED", kinds(findings))
        self.assertIn("DHCP_LEASE_RENEWED", kinds(findings))


class TestFirstSample(unittest.TestCase):
    def test_first_sample_produces_no_change_findings(self):
        findings, attrs = judge(None, obs())
        self.assertEqual(attrs, ["first_sample"])
        self.assertEqual([f for f in findings if f.axis == "security"], [])


class TestAnSsidGapIsNotAMove(unittest.TestCase):
    """위치 헬퍼가 SSID 를 못 준 주기(공백 주기)를 네트워크 이동으로 읽지 않는다(작업 2026-09-27-ssid-gap-network-change).

    실측(09-16~09-27): 헬퍼가 실패한 공백 가운데 앞뒤 인터페이스·SSID·서브넷이 같고 연결이 끊기지 않은 10개(1주기~약 5시간)가
    진입·이탈 때마다 `network_change` 가 붙어 기준선이 초기화되고 도달성 판정(`GATEWAY_ICMP_OK`)이 다시 났다(20건). 공백 주기는 SSID 로 변경을
    가리지 않고, 다시 읽은 SSID 는 마지막으로 읽은 SSID 와 견준다 — 위협 모델 판단 표(docs/threat-model.md)를 그대로 쓴다.
    (20건은 09-16~09-27 전체 — 09-27 의 9개가 18건, 09-23 의 1개가 2건.)
    """

    def setUp(self):
        import os
        import shutil
        import tempfile
        from netmon import config as configmod
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        self.cfg = configmod.load(os.path.join(d, "c.json"))
        # SSID 는 위치 정보 동의가 있을 때만 수집된다(engine.py 의 allow_location = detect.evil_twin)
        self.cfg.set_feature("detect.evil_twin", True)
        self.cfg.grant("location")
        self.n = 0

    def o(self, ssid=SSID, gap=False, skip=0, linkless=False, **kw):
        """5초 간격 관측. gap=True 는 헬퍼가 값을 못 준 주기(수집기가 남기는 모양 — collect/wifi.py). skip 은 앞에 더 벌어진 초
        (측정 공백), linkless 는 주 인터페이스가 없는 주기(엔진이 판정하지 않음 — 수집기는 SSID 를 남기지 않음)."""
        self.n += skip // 5
        ob = obs(ts="2026-01-01T%02d:%02d:%02dZ" % (self.n * 5 // 3600, self.n * 5 // 60 % 60, self.n * 5 % 60),
                 ssid=None if (gap or linkless) else ssid, **kw)
        if gap:
            ob.data["wifi"]["helper_unavailable"] = True
        if linkless:
            ob.data["iface"]["primary"] = None
            ob.data["wifi"]["identity_withheld"] = True
        self.n += 1
        return ob

    def engine(self):
        """replay 와 같게 만든 엔진(주기마다 상태를 들여다보려고)."""
        from netmon import engine as enginemod
        from netmon import investigate
        eng = enginemod.Engine.__new__(enginemod.Engine)
        eng.cfg, eng.store = self.cfg, None
        eng.prev = eng.anchor = eng.prev_wall = None
        eng.link_gap = False
        eng.state = {}
        eng._baseline_saved_at = eng._arp_log_read_at = None
        eng.investigator = investigate.Investigator(self.cfg.data.get("investigate"))
        eng.needs = {}
        return eng

    def never_reset(self, seq):
        """엔진으로 열을 돌려 기준선이 한 번도 지워지지 않았는가(`cycles_on_network` 가 줄지 않고 늘기만 함)."""
        eng, seen = self.engine(), []
        for ob in seq:
            self.step(eng, ob)
            seen.append(eng.state.get("cycles_on_network"))
        return all(b > a for a, b in zip(seen, seen[1:]))

    @staticmethod
    def step(eng, ob, elapsed=5.0):
        from netmon.detect import is_complete
        fs = eng.judge(ob, elapsed)
        if is_complete(ob):
            eng.prev = ob
        return fs

    def run_seq(self, seq):
        from netmon import engine as enginemod
        return enginemod.replay(self.cfg, seq)

    @staticmethod
    def attributed(res, reason):
        return [(i, f.kind) for i, (_, fs) in enumerate(res) for f in fs if f.attribution == reason]

    def test_a_gap_on_the_same_network_is_not_a_move(self):
        """(a) SSID 있음 → 공백 → 있음, 나머지 같음. 지금은 진입·이탈에 network_change 와 기준선 초기화(도달성 판정 재발)."""
        res = self.run_seq([self.o(), self.o(), self.o(gap=True), self.o(), self.o()])
        icmp_ok = [i for i, (_, fs) in enumerate(res) for f in fs if f.kind == "GATEWAY_ICMP_OK"]
        self.assertEqual(len(icmp_ok), 1, "도달성 판정 방법은 처음 한 번만 배운다 — 공백이 기준선을 지우면 다시 난다")
        self.n = 0
        self.assertTrue(self.never_reset([self.o(), self.o(), self.o(gap=True), self.o(), self.o()]))

    # QA-1 ────────────────────────────────────────────────────────────────
    def test_a_long_gap_with_a_measurement_gap_inside_is_only_sleep(self):
        """(i) 공백 중 측정 공백(잠자기) → `SLEEP` 만, 이동 귀속·초기화 없음, 공백 뒤 같은 SSID 도 변경 아님."""
        res = self.run_seq([self.o(), self.o(), self.o(gap=True), self.o(gap=True, skip=120), self.o(gap=True), self.o()])
        self.assertEqual(len([1 for _, fs in res for f in fs if f.kind == "GATEWAY_ICMP_OK"]), 1)
        self.n = 0
        self.assertTrue(self.never_reset([self.o(), self.o(), self.o(gap=True), self.o(gap=True, skip=120), self.o(gap=True),
                                          self.o()]))

    def test_a_vpn_change_in_a_gap_cycle_still_opens_its_own_window(self):
        """공백 주기와 VPN 전환이 겹치면(09-16~23 실측 G1~G4) 공백 없는 VPN 전환처럼 VPN 전환 사유로 창이 열리고, 이동 귀속·초기화는 없다
        (기준 커밋은 같은 주기에 network_change 사유로 창을 열고 기준선을 지웠다)."""
        eng = self.engine()
        for ob in (self.o(vpn=vpn_state()), self.o(vpn=vpn_state())):
            self.step(eng, ob)
        cycles = eng.state.get("cycles_on_network")
        self.step(eng, self.o(gap=True, vpn=vpn_state("disconnected")))
        self.assertTrue(eng.state.get("settle_left_s"))
        self.assertEqual(eng.state.get("settle_reason"), "vpn_change")
        self.assertGreater(eng.state.get("cycles_on_network"), cycles, "기준선이 지워지지 않았다(초기화면 다시 1 부터)")

    def test_a_gap_does_not_repeat_the_silent_gateway_decision(self):
        """ICMP 에 응답하지 않는 게이트웨이 — 공백이 기준선을 지우지 않으므로 `GATEWAY_ICMP_SILENT` 는 한 번만 난다. 출구 뒤에 도달성 판정을
        다시 배울 만큼 주기를 둔다(DEV-1 검수 1회차: 12주기로는 기준 커밋도 1번이라 이 조건을 검사하지 못했다 — 30주기에서 기준 커밋은 2번)."""
        def count(seq):
            return len([1 for _, fs in self.run_seq(seq) for f in fs if f.kind == "GATEWAY_ICMP_SILENT"])
        self.n = 0
        plain = count([self.o(icmp_ok=False) for _ in range(30)])
        self.n = 0
        gapped = count([self.o(icmp_ok=False, gap=(i in (6, 7))) for i in range(30)])
        self.assertEqual((plain, gapped), (1, 1))

    # QA-2 ────────────────────────────────────────────────────────────────
    def test_another_ssid_after_a_gap_is_a_move(self):
        """(b) 공백 뒤 다른 SSID(같은 서브넷) → 마지막으로 읽은 SSID 와 달라 `NETWORK_CHANGE` — 기준선을 지운다."""
        eng = self.engine()
        for ob in (self.o(), self.o(), self.o(gap=True)):
            self.step(eng, ob)
        self.assertGreater(eng.state.get("cycles_on_network"), 1)
        self.step(eng, self.o(ssid="OtherNet"))
        self.assertEqual(eng.state.get("cycles_on_network"), 1, "다른 네트워크로 옮겼으니 기준선을 새로 배운다")

    def test_a_subnet_change_in_a_gap_cycle_is_a_move(self):
        """(c) 공백 주기에 서브넷이 바뀜 → `NETWORK_CHANGE`(SSID 를 몰라도 서브넷은 본다)."""
        res = self.run_seq([self.o(), self.o(), self.o(gap=True, gateway=GW2, routers=(GW2,), my_ip="198.51.100.50",
                                                        dhcp_server=DHCP_SRV2, gw_mac=GW2_MAC)])
        self.assertTrue(any(f.attribution == "network_change" for f in res[2][1]))

    def test_the_same_ssid_after_a_gap_and_a_link_break_is_not_a_move(self):
        """(g) G2 모양 — 공백 주기 → 링크 없는 주기 → 같은 SSID·서브넷: 이동 귀속 없음(공백 없는 재접속과 같음), 창은 링크 단절로 열림."""
        eng = self.engine()
        for ob in (self.o(), self.o(), self.o(gap=True), self.o(linkless=True), self.o(linkless=True)):
            self.step(eng, ob)
        cycles = eng.state.get("cycles_on_network")
        self.step(eng, self.o())
        self.assertGreater(eng.state.get("cycles_on_network"), cycles, "이동이면 기준선이 지워져 1 부터 센다")
        self.assertEqual(eng.state.get("settle_reason"), "link_restart")

    def test_an_evil_twin_behind_a_gap_and_a_link_break_is_not_excused(self):
        """(h)·ADV-2(1) deauth 모양 — 공백 주기 → 링크 없는 주기 → 같은 SSID·서브넷·다른 게이트웨이 MAC: 공백 없는 같은 재접속과 같은
        등급(억제 안 함 — 판단 표 "SSID 같음, MAC 바뀜"). 지금까지는 출구가 공백 주기의 "-" 와 견줘 network_change 로 low 였다."""
        def exit_mac_change(with_gap):
            self.n = 0
            seq = [self.o(), self.o()] + ([self.o(gap=True)] if with_gap else []) + \
                  [self.o(linkless=True), self.o(linkless=True), self.o(gw_mac=GW_MAC_ALT)]
            f = by_kind(self.run_seq(seq)[-1][1], "GW_MAC_CHANGED")
            return (f.severity, f.attribution) if f else None
        self.assertEqual(exit_mac_change(True), exit_mac_change(False))
        self.assertEqual(exit_mac_change(True), ("high", None))

    # QA-3 ────────────────────────────────────────────────────────────────
    def test_a_gap_right_after_a_link_break_is_a_possible_move_and_forgets_the_ssid(self):
        """(f)·ADV-2(2) G5 모양 — 링크 없는 주기 뒤 첫 판정 주기가 공백이고 게이트웨이 MAC·IP 가 바뀜: 판단 표 "SSID 모름·링크 재시작" 줄
        대로 등급을 낮춘다(지금과 같은 low — 귀속 이름만 network_change → link_restart). 읽은 SSID 를 잊어, 다음 읽기는 지금처럼 이동이다
        (남는 한계 두 주기)."""
        eng = self.engine()
        for ob in (self.o(), self.o(), self.o(linkless=True), self.o(linkless=True)):
            self.step(eng, ob)
        f = by_kind(self.step(eng, self.o(gap=True, gw_mac=GW_MAC_ALT, my_ip="192.0.2.77", lease_start="2026-01-01 00:01:00")),
                    "GW_MAC_CHANGED")
        self.assertEqual(f.severity, "low")
        self.assertIsNotNone(f.attribution)
        self.assertIsNone(getattr(eng, "identity_ssid", None))
        self.step(eng, self.o(gw_mac=GW_MAC_ALT, my_ip="192.0.2.77", lease_start="2026-01-01 00:01:00"))
        self.assertEqual(eng.state.get("cycles_on_network"), 1, "잊은 뒤 첫 읽기는 공백 주기의 \"-\" 와 견줘 이동(지금과 같음)")

    def consent_off_and_back(self, eng):
        for ob in (self.o(), self.o()):
            self.step(eng, ob)
        before = getattr(eng, "identity_ssid", None)
        self.cfg.revoke("location")
        withheld = self.o(gap=False, ssid=None)
        withheld.data["wifi"]["identity_withheld"] = True
        self.step(eng, withheld)
        during = getattr(eng, "identity_ssid", None)
        self.cfg.grant("location")
        self.step(eng, self.o())
        return before, during

    def test_turning_the_location_consent_off_forgets_the_ssid(self):
        """(e 뒷부분) 동의를 끄면 읽은 SSID 를 잊는다(새 내부 값 — 기준 커밋에는 없음)."""
        self.assertEqual(self.consent_off_and_back(self.engine()), (SSID, None))

    def test_the_first_read_after_the_consent_comes_back_is_judged_as_before(self):
        """(e 뒷부분, K-7) 동의를 다시 켠 뒤 첫 읽기는 지금처럼 기준 관측(동의 없이 기록한 "-")과 견줘 이동이다 — 기준 커밋과 같다."""
        eng = self.engine()
        self.consent_off_and_back(eng)
        self.assertEqual(eng.state.get("cycles_on_network"), 1)

    def test_a_gap_is_a_gap_whatever_the_reason(self):
        """공백 판별은 사유를 보지 않는다(SPEC 가정 2, K-3) — 헬퍼가 빈 SSID 를 줌(`helper_unavailable` 없음, 위치 헬퍼로 읽힘 표지)이나
        ipconfig 가 빈 값을 줌(권한 있음)도 헬퍼 실패와 같게 이동이 아니다(DEV-1 검수 1회차: 모든 픽스처가 helper_unavailable 을 붙여
        공백 판별을 그 표지로 바꾼 변이가 살아남았다)."""
        for name, mark in (("헬퍼 빈 SSID", {"location": "granted-via-helper", "source": "location-helper"}),
                           ("ipconfig 빈 값", {"location": "granted", "source": "ipconfig"})):
            with self.subTest(name):
                self.n = 0
                gap = self.o(ssid=None)
                gap.data["wifi"].update(mark)
                self.assertNotIn("helper_unavailable", gap.data["wifi"])
                res = self.run_seq([self.o(), self.o(), gap, self.o()])
                self.assertEqual(len([1 for _, fs in res for f in fs if f.kind == "GATEWAY_ICMP_OK"]), 1)

    def test_without_the_consent_the_last_read_ssid_is_not_used(self):
        """동의가 꺼져 있으면 마지막으로 읽은 SSID 를 쓰지 않고 지금처럼 기준 관측과 견준다 — 동의 없이 표본을 다시 판정해도(표본에
        SSID 가 남아 있어도) 동의의 경계를 넘지 않는다. 공백 주기 뒤 읽은 SSID 가 공백 전과 같아도 기준 관측("-")과 달라 이동이다."""
        eng = self.engine()
        for ob in (self.o(), self.o(), self.o(gap=True)):
            self.step(eng, ob)
        self.cfg.revoke("location")
        self.step(eng, self.o())
        self.assertEqual(eng.state.get("cycles_on_network"), 1)

    def test_a_first_gap_cycle_without_any_link_evidence_is_judged_as_the_same_network(self):
        """남는 한계 (나) — 링크 근거가 남지 않은 첫 판정 주기가 공백이면(예: 링크가 없는 동안 에이전트가 재시작해 링크 공백 표지를 잃음)
        판단 표 "SSID 모름·링크 멀쩡" 줄대로 게이트웨이 MAC 변화를 억제하지 않는다. 기준 커밋은 공백 주기를 "-" 대 앵커 SSID 로 견줘
        network_change·low 로 냈다 — 실제로 옮긴 경우라면 새 동작은 경보(high)가 된다. 의도한 변경이고, 문서(AC-8)에 적는다."""
        eng = self.engine()
        for ob in (self.o(), self.o()):
            self.step(eng, ob)
        eng.link_gap = False                    # 재시작으로 표지를 잃은 모양(엔진은 링크 공백 표지를 저장하지 않는다)
        f = by_kind(self.step(eng, self.o(gap=True, gw_mac=GW_MAC_ALT), elapsed=5.0), "GW_MAC_CHANGED")
        self.assertEqual((f.severity, f.attribution), ("high", None))

    # QA-6 (K-7 — 기준 커밋에서도 통과해야 한다: replay·관측만 쓴다) ────────────────
    def test_paths_without_a_gap_keep_their_attribution(self):
        """(e) 동의 없음·주 인터페이스가 Wi-Fi 아님·SSID 를 한 번도 못 읽음·공백 없는 이동·공백 없는 재접속의 게이트웨이 MAC 변화는
        기준 커밋과 같은 (등급, 귀속)이다."""
        def withheld(**kw):
            ob = self.o(ssid=None, **kw)
            ob.data["wifi"]["identity_withheld"] = True
            return ob
        cases = {
            "동의 없음": (lambda: [withheld(), withheld(), withheld(gw_mac=GW_MAC_ALT)], ("high", None)),
            "Wi-Fi 아님": (lambda: [self.o(ssid=None, iface_kind="ethernet"), self.o(ssid=None, iface_kind="ethernet"),
                                     self.o(ssid=None, iface_kind="ethernet", gw_mac=GW_MAC_ALT)], ("high", None)),
            "한 번도 못 읽음": (lambda: [self.o(gap=True), self.o(gap=True), self.o(gap=True, gw_mac=GW_MAC_ALT)], ("high", None)),
            "공백 없는 SSID 이동": (lambda: [self.o(), self.o(), self.o(ssid="OtherNet", gw_mac=GW_MAC_ALT)],
                                    ("low", "network_change")),
            "공백 없는 재접속": (lambda: [self.o(), self.o(), self.o(linkless=True), self.o(gw_mac=GW_MAC_ALT)], ("high", None)),
        }
        for name, (make, want) in cases.items():
            with self.subTest(name):
                self.n = 0
                f = by_kind(self.run_seq(make())[-1][1], "GW_MAC_CHANGED")
                self.assertEqual((f.severity, f.attribution), want)

    def test_an_interface_or_subnet_move_without_a_gap_is_still_a_move(self):
        for name, last in (("인터페이스", dict(iface="en1")),
                           ("서브넷", dict(gateway=GW2, routers=(GW2,), my_ip="198.51.100.50", dhcp_server=DHCP_SRV2,
                                         gw_mac=GW2_MAC))):
            with self.subTest(name):
                eng = self.engine()
                self.n = 0
                for ob in (self.o(), self.o(), self.o(**last)):
                    self.step(eng, ob)
                self.assertEqual(eng.state.get("cycles_on_network"), 1, "옮겼으니 기준선을 새로 배운다")

    def test_a_mac_change_inside_a_gap_without_a_link_break_is_not_excused(self):
        """판단 표 넷째 줄 — SSID 모름, 링크 멀쩡, MAC 바뀜 → 억제하지 않음. 지금은 공백 주기가 network_change 로 읽혀 low."""
        res = self.run_seq([self.o(), self.o(), self.o(gap=True, gw_mac=GW_MAC_ALT)])
        f = by_kind(res[2][1], "GW_MAC_CHANGED")
        self.assertIsNotNone(f)
        self.assertEqual((f.severity, f.attribution), ("high", None))


class TestAnSsidGapDoesNotCloseAnInvestigation(unittest.TestCase):
    """공백만으로 열린 조사가 "네트워크가 바뀌어 중단" 으로 닫히지 않는다(AC-4, QA-4, ADV-3 — 작업 2026-09-27-ssid-gap-network-change DEV-2).
    판정·상태·조사 기록의 `network` 는 관측값 그대로이고, 중단 비교만 SSID 자리의 "-" 를 마지막으로 읽은 SSID 와 같은 것으로 본다.
    GW_MAC_CHANGED(high, 귀속 없음)가 l2_identity 조사를 연다.
    """

    # 도우미만 가져온다(상속하면 위 클래스의 시험이 한 번 더 돈다)
    setUp = TestAnSsidGapIsNotAMove.setUp
    o = TestAnSsidGapIsNotAMove.o
    run_seq = TestAnSsidGapIsNotAMove.run_seq
    engine = TestAnSsidGapIsNotAMove.engine
    step = staticmethod(TestAnSsidGapIsNotAMove.step)

    @staticmethod
    def kinds_of(res, *kinds):
        return [(i, f.kind) for i, (_, fs) in enumerate(res) for f in fs if f.kind in kinds]

    def test_an_investigation_opened_before_a_gap_survives_it(self):
        """(d) 공백 전에 연 조사는 공백 동안도, 공백 뒤 같은 SSID 를 읽은 주기에도 닫히지 않는다."""
        res = self.run_seq([self.o(), self.o(), self.o(gw_mac=GW_MAC_ALT), self.o(gap=True, gw_mac=GW_MAC_ALT),
                            self.o(gap=True, gw_mac=GW_MAC_ALT), self.o(gw_mac=GW_MAC_ALT)])
        self.assertEqual(self.kinds_of(res, "INVESTIGATION_OPENED"), [(2, "INVESTIGATION_OPENED")])
        self.assertEqual(self.kinds_of(res, "INVESTIGATION_ABANDONED"), [])

    def test_an_investigation_opened_in_a_gap_survives_the_same_ssid_after_it(self):
        """(l) 공백 중에 연 조사(관측 키의 SSID 자리가 "-")는 공백이 끝나 같은 SSID 를 읽은 주기에 닫히지 않는다."""
        res = self.run_seq([self.o(), self.o(), self.o(gap=True), self.o(gap=True, gw_mac=GW_MAC_ALT), self.o(gw_mac=GW_MAC_ALT)])
        self.assertEqual(self.kinds_of(res, "INVESTIGATION_OPENED"), [(3, "INVESTIGATION_OPENED")])
        self.assertEqual(self.kinds_of(res, "INVESTIGATION_ABANDONED"), [])

    def test_another_ssid_after_a_gap_still_closes_it(self):
        """부정 사례(K-7) — 공백 중에 연 조사는 공백 뒤 **다른** SSID(같은 서브넷)를 읽으면 닫힌다. 기준 커밋과 같다."""
        res = self.run_seq([self.o(), self.o(), self.o(gap=True), self.o(gap=True, gw_mac=GW_MAC_ALT),
                            self.o(ssid="OtherNet", gw_mac=GW_MAC_ALT)])
        self.assertEqual(self.kinds_of(res, "INVESTIGATION_ABANDONED"), [(4, "INVESTIGATION_ABANDONED")])

    def test_a_subnet_change_in_a_gap_cycle_still_closes_it(self):
        """부정 사례(K-7) — 공백 주기에 서브넷이 바뀌면 공백 전에 연 조사는 닫힌다. 기준 커밋과 같다."""
        res = self.run_seq([self.o(), self.o(), self.o(gw_mac=GW_MAC_ALT),
                            self.o(gap=True, gateway=GW2, routers=(GW2,), my_ip="198.51.100.50", dhcp_server=DHCP_SRV2,
                                   gw_mac=GW2_MAC)])
        self.assertEqual(self.kinds_of(res, "INVESTIGATION_ABANDONED"), [(3, "INVESTIGATION_ABANDONED")])

    def test_forgetting_the_ssid_in_a_gap_cycle_closes_it_as_before(self):
        """(K-7) 공백 주기에 이동 귀속이 붙어 읽은 SSID 를 잊는 주기(G5 모양)에는 지금처럼 그 주기에 닫힌다 — 잊기가 비교보다 먼저다(K-2)."""
        res = self.run_seq([self.o(), self.o(), self.o(gw_mac=GW_MAC_ALT), self.o(linkless=True),
                            self.o(gap=True, gw_mac=GW_MAC_ALT, my_ip="192.0.2.77", lease_start="2026-01-01 00:01:00")])
        self.assertEqual(self.kinds_of(res, "INVESTIGATION_ABANDONED"), [(4, "INVESTIGATION_ABANDONED")])

    def test_the_network_value_stays_the_observed_one(self):
        """(k)(K-7) 판정의 `network`·상태의 `network` 는 공백 주기에도 관측값(SSID 자리 "-") — 기존 키의 뜻을 바꾸지 않는다."""
        from netmon.detect import network_key
        eng = self.engine()
        for ob in (self.o(), self.o()):
            self.step(eng, ob)
        gap = self.o(gap=True, gw_mac=GW_MAC_ALT)
        fs = [f for f in self.step(eng, gap) if not f.kind.startswith("INVESTIGATION_")]   # 조사 판정은 원래 network 를 달지 않음
        self.assertTrue(fs)
        self.assertEqual({f.network for f in fs}, {network_key(gap)})
        self.assertIn("|-|", network_key(gap))
        self.assertEqual(eng.state.get("network"), network_key(gap))

    def test_an_investigation_opened_in_a_gap_records_the_observed_key(self):
        """(k) 공백 주기에 열린 조사의 기록(`network`)도 관측 키(SSID 자리 "-")다 — 대체 키를 기록에 쓰지 않는다(DEV-2 검수 1회차 [낮음]).
        기준 커밋은 공백 주기의 MAC 변화를 억제해 이 조사가 열리지 않으므로 새 코드 전용이다."""
        from netmon.detect import network_key
        eng = self.engine()
        for ob in (self.o(), self.o()):
            self.step(eng, ob)
        gap = self.o(gap=True, gw_mac=GW_MAC_ALT)
        self.assertIn("INVESTIGATION_OPENED", [f.kind for f in self.step(eng, gap)])
        self.assertEqual([i.get("network") for i in eng.state.get("investigations", []) if i.get("status") == "open"],
                         [network_key(gap)])

    def test_an_empty_wifi_block_still_closes_it_as_before(self):
        """(K-7) 수집기 예외로 Wi-Fi 블록이 빈 주기는 공백이 아니다 — 대체 키 없이 지금처럼 닫힌다(DEV-2 검수 1회차 [참고]: 대체 키에서
        공백 판별을 뺀 변이 M3 가 살아남았다)."""
        empty = self.o(gw_mac=GW_MAC_ALT)
        empty.data["wifi"] = {}
        res = self.run_seq([self.o(), self.o(), self.o(gw_mac=GW_MAC_ALT), empty])
        self.assertEqual(self.kinds_of(res, "INVESTIGATION_ABANDONED"), [(3, "INVESTIGATION_ABANDONED")])

    def test_an_ssid_with_the_separator_does_not_join_two_networks(self):
        """ADV-3 — SSID 는 AP 가 정하는 값이라 `|` 를 품을 수 있다. 조사 비교가 키를 쪼개지 않으므로, SSID 에 다른 네트워크의 키 조각을
        넣어도 그 네트워크의 조사를 "같은 네트워크" 로 이어받지 못한다."""
        from netmon.detect import network_key, network_key_with
        home = self.o()
        forged = "%s|%s" % (SSID, network_key(home).split("|")[-1])       # "ExampleNet|<서브넷>"
        gap = self.o(gap=True, gateway=GW2, routers=(GW2,), my_ip="198.51.100.50", dhcp_server=DHCP_SRV2)
        self.assertNotEqual(network_key_with(gap, forged), network_key(home))
        res = self.run_seq([home, self.o(), self.o(gw_mac=GW_MAC_ALT), self.o(ssid=forged, gateway=GW2, routers=(GW2,),
                                                                            my_ip="198.51.100.50", dhcp_server=DHCP_SRV2), gap])
        # 다른 네트워크의 첫 주기(3)에 닫힌다 — 키를 `|` 로 쪼개 앞 조각만 견주면 한 주기 이어받는다(DEV-2 검수 1회차 변이 M2)
        self.assertEqual(self.kinds_of(res, "INVESTIGATION_ABANDONED"), [(3, "INVESTIGATION_ABANDONED")])


class TestIdentityRuleOverEveryBranch(unittest.TestCase):
    """`attributions_for` 의 정체성 규칙을 입력 갈래의 곱으로 돈다(작업 2026-09-27-ssid-gap-network-change K-6, 교훈
    2026-09-27-pin-values-and-boundaries). 기대는 코드가 아니라 명세 AC-1·AC-2·K-5 와 위협 모델 판단 표에서 옮긴 것이다:

      - 인터페이스가 다르면 `iface_change`(정체성은 그것으로 끝).
      - 인터페이스가 같으면: 서브넷이 다르면 `network_change`. 서브넷이 같을 때 SSID 는
          · 이번 주기가 공백 주기 → 모름(판단 표 "SSID 모름") — SSID 로는 변경이 아니다.
          · 이번 주기에 SSID 를 읽었고 마지막으로 읽은 SSID 가 있음 → 그것과 다르면 이동.
          · 그 밖(읽은 SSID 없음, 동의 없음·Wi-Fi 아님) → 기준 관측의 SSID 자리("-" 포함)와 다르면 이동(지금까지의 규칙).
      - 이동 귀속이 없고 이번 주기에 SSID 를 실제로 읽지 못했으며 링크 근거(링크 없는 주기·링크 재시작)가 있으면 `link_restart`.
      - 측정 간격이 벌어졌으면 `sleep`(정체성과 무관하게 함께).

    엔진에서 드문 조합도 돈다 — 기준 관측이 SSID 를 읽었는데 읽은 SSID 가 없는 것은 동의가 꺼져 있을 때(엔진이 읽은 SSID 를 넘기지 않음)와
    재시작 뒤 되살린 값이 없을 때만 생기고, 읽은 SSID 가 기준 관측의 SSID 와 다른 것은 엔진에서 생기지 않는다(앵커가 읽은 주기면 그 주기에
    같은 값이 기록됨). 규칙이 입력만으로 정해지는지를 보려고 그대로 둔다. 새 인자(`last_ssid`)를 부르므로 새 코드 전용이다.
    """

    S, T = SSID, "OtherNet"

    def cur_obs(self, kind, iface, subnet, restarted):
        kw = dict(iface=iface, link_active="TRUE")
        if subnet == "다름":
            kw.update(gateway=GW2, routers=(GW2,), my_ip="198.51.100.50", dhcp_server=DHCP_SRV2)
        if kind == "읽음S":
            o = obs(ssid=self.S, **kw)
        elif kind == "읽음T":
            o = obs(ssid=self.T, **kw)
        elif kind == "공백":
            o = obs(ssid=None, **kw)
            o.data["wifi"]["helper_unavailable"] = True
        elif kind == "동의 없음":
            o = obs(ssid=None, **kw)
            o.data["wifi"]["identity_withheld"] = True
        else:                                   # Wi-Fi 아님
            o = obs(ssid=None, iface_kind="ethernet", **kw)
        return o

    def base_obs(self, kind, restarted):
        o = obs(ssid=self.S if kind == "읽음S" else None, link_active="FALSE" if restarted else "TRUE")
        if kind == "공백":
            o.data["wifi"]["helper_unavailable"] = True
        return o

    def expected(self, cur_kind, base_kind, last, link, subnet, iface, sleep):
        want = set()
        if sleep:
            want.add("sleep")
        if iface == "다름":
            want.add("iface_change")
            return want
        cur_ssid = {"읽음S": self.S, "읽음T": self.T}.get(cur_kind)
        base_part = self.S if base_kind == "읽음S" else "-"
        if subnet == "다름":
            moved = True
        elif cur_kind == "공백":
            moved = False
        elif cur_ssid is not None and last is not None:
            moved = cur_ssid != last
        else:
            moved = base_part != (cur_ssid or "-")
        if moved:
            want.add("network_change")
        elif cur_ssid is None and link != "없음":
            want.add("link_restart")
        return want

    def test_every_branch(self):
        import itertools
        from netmon.detect import attributions_for
        n = 0
        for cur_kind, base_kind, last, link, subnet, iface, sleep in itertools.product(
                ("읽음S", "읽음T", "공백", "동의 없음", "Wi-Fi 아님"), ("읽음S", "공백"), (None, self.S, self.T),
                ("없음", "링크 없는 주기", "링크 재시작"), ("같음", "다름"), ("같음", "다름"), (False, True)):
            base = self.base_obs(base_kind, link == "링크 재시작")
            cur = self.cur_obs(cur_kind, "en1" if iface == "다름" else "en0", subnet, link == "링크 재시작")
            got = set(attributions_for(base, cur, 120.0 if sleep else 5.0, 5.0, anchor=base,
                                       link_gap=(link == "링크 없는 주기"), last_ssid=last))
            got &= {"sleep", "iface_change", "network_change", "link_restart"}
            with self.subTest(cur=cur_kind, base=base_kind, last=last, link=link, subnet=subnet, iface=iface, sleep=sleep):
                self.assertEqual(got, self.expected(cur_kind, base_kind, last, link, subnet, iface, sleep))
            n += 1
        self.assertEqual(n, 720)


class TestTheLastReadSsidUpdateRule(unittest.TestCase):
    """마지막으로 읽은 SSID 의 갱신 규칙(detect.next_last_ssid — 작업 2026-09-27-ssid-gap-network-change K-6). 기대는 명세 AC-3 에서:
    읽었으면 그 값, 공백 주기에 이동 귀속(iface_change·network_change·link_restart)이면 잊음, 공백 주기에 잠자기·VPN 전환만이면 유지,
    공백도 아니고 읽지도 않은 주기(동의 없음·Wi-Fi 아님)는 유지. 동의가 꺼졌을 때 지우는 것은 엔진의 몫(TestAnSsidGapIsNotAMove).
    """

    def test_every_branch(self):
        import itertools
        from netmon.detect import next_last_ssid
        moves = ("iface_change", "network_change", "link_restart")
        for kind, last, attrs in itertools.product(
                ("읽음", "공백", "동의 없음", "Wi-Fi 아님"), (None, SSID),
                ([], ["sleep"], ["vpn_change"], ["sleep", "vpn_change"], ["iface_change"], ["network_change"], ["link_restart"],
                 ["sleep", "link_restart"])):
            if kind == "읽음":
                cur = obs(ssid="OtherNet")
            elif kind == "공백":
                cur = obs(ssid=None)
                cur.data["wifi"]["helper_unavailable"] = True
            elif kind == "동의 없음":
                cur = obs(ssid=None)
                cur.data["wifi"]["identity_withheld"] = True
            else:
                cur = obs(ssid=None, iface_kind="ethernet")
            if kind == "읽음":
                want = "OtherNet"
            elif kind == "공백" and any(a in attrs for a in moves):
                want = None
            else:
                want = last
            with self.subTest(kind=kind, last=last, attrs=attrs):
                self.assertEqual(next_last_ssid(last, cur, attrs), want)


if __name__ == "__main__":
    unittest.main()
