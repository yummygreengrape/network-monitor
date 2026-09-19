"""첫 홉 복구 판정이 한 번도 뜨지 않던 문제.

기준선 갱신(`baseline.update_counters`)이 판정(`run_all`)보다 먼저 돌면서
성공 주기에 `gw_fail_streak` 을 0 으로 만든다. 복구 분기는 그 값이 2 이상일
것을 요구했으므로 **조건이 영원히 거짓**이었다.

양쪽 기계 전체 기록에서 확인: FIRST_HOP_UNREACHABLE 10건, FIRST_HOP_RECOVERED 0건.
이 판정에는 테스트가 아예 없었다 — 그래서 아무도 잡지 못했다.
값은 전부 문서용 대역이다.
"""
from __future__ import annotations

import datetime
import os
import re
import shutil
import tempfile
import unittest

from netmon import baseline
from netmon import config as configmod
from netmon import messages
from netmon.detect import Context, is_complete, network_key, quality, run_all
from netmon.engine import Engine
from netmon.investigate import triggers
from netmon.store import Store
from tests.helpers import (DHCP_SRV2, GW2, GW2_MAC, SSID, by_kind, kinds, obs)

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

    def test_a_two_cycle_gap_is_logged_as_info_not_alerted(self):
        # 2026-09-20: 10초짜리 공백이 30분마다 되풀이됐는데 같은 순간 외부 경로는
        # 멀쩡했다. 공유기의 ICMP 무시였지 연결 끊김이 아니었다.
        # (위 근거 문장은 측정된 범위로 따로 고친다. 2회 공백은 이제 info 로 남긴다.)
        seen = self._run([False, False, True])
        self.assertFalse(any("FIRST_HOP_UNREACHABLE" in s for s in seen))
        self.assertFalse(any("FIRST_HOP_RECOVERED" in s for s in seen))
        self.assertEqual(seen[2].count("FIRST_HOP_BRIEF_GAP"), 1)
        self.assertEqual(sum(s.count("FIRST_HOP_BRIEF_GAP") for s in seen), 1)

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


# ───────────────────────── 2회 공백을 info 로 남기기 (FIRST_HOP_BRIEF_GAP)
#
# 아래 시험은 주기 순서를 글자로 적는다.
#   S 성공   F 실패(ICMP 무응답, ARP 정상)   N 판정 불가(ICMP 결과 없음)
#   A 주 인터페이스 없음(LINK_ABSENT)

BRIEF = "FIRST_HOP_BRIEF_GAP"
DOWN = "FIRST_HOP_UNREACHABLE"
BACK = "FIRST_HOP_RECOVERED"
T0 = 1767225600.0          # 2026-01-01T00:00:00Z
MISSING = object()
# 없음 / 숫자 아닌 문자열 / 숫자 문자열 / None / 음수
BAD_VALUES = (MISSING, "x", "2", None, -1)


def _ts(wall):
    return datetime.datetime.fromtimestamp(wall, datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def _make(code, wall, ssid=None):
    ts = _ts(wall)
    if code == "S":
        return obs(ts=ts, icmp_ok=True, rtt=3.0, ssid=ssid)
    if code == "F":
        return obs(ts=ts, icmp_ok=False, rtt=None, ssid=ssid)
    if code == "N":
        o = obs(ts=ts, icmp_ok=True, rtt=3.0, ssid=ssid)
        del o.data["link"]["gateway_reachable"]
        return o
    if code == "A":
        o = obs(ts=ts, ssid=None, gw_mac=None, icmp_ok=None, rtt=None)
        o.data["iface"]["primary"] = None
        o.data["iface"]["default4_gateway"] = None
        return o
    if code == "M":   # 다른 서브넷으로 옮김. ARP 정상, ICMP 실패
        return obs(ts=ts, gateway=GW2, gw_mac=GW2_MAC, dhcp_server=DHCP_SRV2,
                   routers=(GW2,), dns=(GW2,), resolvers=(GW2,),
                   my_ip="198.51.100.50", icmp_ok=False, rtt=None, ssid=ssid)
    raise ValueError(code)


def _fresh_engine(folder):
    # 없는 경로를 주면 기본 설정만 쓴다. 이 기계의 설정에 결과가 좌우되지 않게 한다.
    return Engine(configmod.load(os.path.join(folder, "no-config.json")), Store(folder))


class _Drive:
    """engine.replay 와 같은 순서로 Engine.judge 를 돌린다."""

    def __init__(self, eng, wall=T0):
        self.eng = eng
        self.wall = wall

    def step(self, o, gap=5.0):
        self.wall += gap
        elapsed = (self.wall - self.eng.prev_wall) if self.eng.prev_wall else 0.0
        found = self.eng.judge(o, elapsed)
        if is_complete(o):
            self.eng.prev = o
        self.eng.prev_wall = self.wall
        return found

    def run(self, codes, ssid=None, gaps=None):
        out = []
        for i, code in enumerate(codes):
            gap = (gaps or {}).get(i, 5.0)
            out.append(self.step(_make(code, self.wall + gap, ssid), gap))
        return out


class _EngineCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.addCleanup(messages.set_language, "ko")

    def drive(self, codes, ssid=None, gaps=None, language=None):
        """첫 주기는 ICMP 보정을 끝내는 성공 주기. 그 뒤 codes 의 판정 목록."""
        d = _Drive(_fresh_engine(self.dir))
        if language:
            # Engine 생성이 설정의 언어로 되돌리므로 그 뒤에 바꾼다
            messages.set_language(language)
        d.run("S", ssid=ssid)
        self.assertIs(d.eng.state.get("icmp_gw"), True)
        return d, d.run(codes, ssid=ssid, gaps=gaps)

    def first_hop(self, per_cycle):
        return [[f.kind for f in found if f.kind.startswith("FIRST_HOP")]
                for found in per_cycle]

    def assertNoError(self, per_cycle):
        for found in per_cycle:
            self.assertNotIn("DETECTOR_ERROR", kinds(found),
                             [f.summary for f in found if f.kind == "DETECTOR_ERROR"])


class TestBriefGap(_EngineCase):
    """QA-1·QA-3·QA-4: 연속 실패 횟수별 판정."""

    def test_two_failures_then_success_logs_one_info(self):
        _d, seen = self.drive("FFS")
        self.assertEqual(self.first_hop(seen), [[], [], [BRIEF]])
        f = by_kind(seen[2], BRIEF)
        self.assertEqual(f.axis, "quality")
        self.assertEqual(f.severity, "info")

    def test_three_or_more_failures_keep_alert_and_recovery(self):
        for n in (3, 4, 6):
            with self.subTest(failures=n):
                _d, seen = self.drive("F" * n + "S")
                got = self.first_hop(seen)
                expect = [[] for _ in range(n + 1)]
                expect[2] = [DOWN]
                expect[n] = [BACK]
                self.assertEqual(got, expect)
                self.assertEqual(by_kind(seen[2], DOWN).severity, "medium")
                self.assertEqual(by_kind(seen[n], BACK).evidence["streak"], n)

    def test_one_failure_then_success_is_silent(self):
        _d, seen = self.drive("FS")
        self.assertEqual(self.first_hop(seen), [[], []])

    def test_brief_gap_is_not_repeated_while_healthy(self):
        _d, seen = self.drive("FFSSS")
        self.assertEqual(sum(k.count(BRIEF) for k in self.first_hop(seen)), 1)


class TestBriefGapWording(_EngineCase):
    """QA-2: 문구에 주기 수와 판정 방법, 근거에 streak·method."""

    def test_evidence_has_streak_and_method(self):
        _d, seen = self.drive("FFS")
        f = by_kind(seen[2], BRIEF)
        self.assertEqual(f.evidence["streak"], 2)
        self.assertEqual(f.evidence["method"], "icmp")

    def test_summary_names_the_count_and_the_method_in_both_languages(self):
        for code in messages.available():
            with self.subTest(language=code):
                _d, seen = self.drive("FFS", language=code)
                f = by_kind(seen[2], BRIEF)
                self.assertEqual(f.summary,
                                 messages.get(BRIEF, code) % (2, quality.METHOD_LABEL["icmp"]))
                self.assertIn("2", f.summary)
                self.assertIn(quality.METHOD_LABEL["icmp"], f.summary)
                messages.set_language("ko")

    def test_placeholders_agree(self):
        spec = re.compile(r"%[-#0 +]*[\d.*]*[a-zA-Z%]")
        self.assertEqual(spec.findall(messages.get(BRIEF, "ko")),
                         spec.findall(messages.get(BRIEF, "en")))
        self.assertEqual(spec.findall(messages.get(BRIEF, "ko")), ["%d", "%s"])


class TestBriefGapDoesNotOpenInvestigations(_EngineCase):
    """QA-5: 조사 트리거가 아니다."""

    def test_not_in_the_default_trigger_kinds(self):
        self.assertNotIn(BRIEF, triggers.DEFAULT_RULES["kinds"])

    def test_the_finding_alone_is_not_meaningful(self):
        _d, seen = self.drive("FFS")
        f = by_kind(seen[2], BRIEF)
        self.assertFalse(triggers.is_meaningful(f, triggers.merge_rules(None)))

    def test_not_in_the_playbook_link_kinds(self):
        import netmon.investigate.playbooks as pb
        with open(pb.__file__, encoding="utf-8") as fh:
            self.assertNotIn(BRIEF, fh.read())

    def test_no_investigation_opens_on_a_brief_gap(self):
        _d, seen = self.drive("FFSSS")
        self.assertFalse(any(k.startswith("INVESTIGATION") for found in seen
                             for k in kinds(found)))


class TestUntrustedCounters(_EngineCase):
    """ADV-1: 상태의 연속 실패 값이 비정상이어도 예외 없이 0 으로 본다."""

    def _state(self, bad):
        st = {"icmp_gw": True}
        if bad is not MISSING:
            st["gw_fail_streak"] = bad
            st["gw_fail_streak_prev"] = bad
        return st

    def test_baseline_path(self):
        for bad in BAD_VALUES:
            with self.subTest(value=bad):
                up = baseline.update_counters(self._state(bad), _make("S", T0), [], 5.0, 5.0)
                self.assertEqual(up["gw_fail_streak"], 0)
                self.assertEqual(up["gw_fail_streak_prev"], 0)
                down = baseline.update_counters(self._state(bad), _make("F", T0), [], 5.0, 5.0)
                self.assertEqual(down["gw_fail_streak"], 1)
                self.assertEqual(down["gw_fail_streak_prev"], 0)

    def test_quality_path_through_an_undecidable_cycle(self):
        # 판정 불가 주기는 update_counters 가 두 값을 건드리지 않으므로
        # 비정상 값이 판정까지 그대로 간다.
        for bad in BAD_VALUES:
            with self.subTest(value=bad):
                d, _ = self.drive("")
                d.eng.state.pop("gw_fail_streak", None)
                d.eng.state.pop("gw_fail_streak_prev", None)
                d.eng.state.update({k: v for k, v in self._state(bad).items()})
                seen = d.run("N")
                if bad is not MISSING:
                    self.assertEqual(d.eng.state["gw_fail_streak"], bad,
                                     "판정 불가 주기가 값을 덮어쓰면 이 경로를 시험하지 못한다")
                self.assertNoError(seen)
                self.assertEqual(self.first_hop(seen), [[]])

    def test_quality_detect_called_directly(self):
        prev = _make("S", T0)
        for bad in BAD_VALUES:
            for code in ("S", "F"):
                with self.subTest(value=bad, cycle=code):
                    ctx = Context(elapsed=5.0, interval=5.0, features=ON,
                                  state=self._state(bad), attributions=[],
                                  network=network_key(prev))
                    found = quality.detect(prev, _make(code, T0 + 5), ctx)
                    self.assertEqual([f.kind for f in found
                                      if f.kind.startswith("FIRST_HOP")], [])

    def test_fail_count(self):
        for bad in BAD_VALUES[1:] + (True, float("nan"), float("inf"), [], {}):
            self.assertEqual(baseline.fail_count(bad), 0, repr(bad))
        self.assertEqual(baseline.fail_count(0), 0)
        self.assertEqual(baseline.fail_count(2), 2)
        self.assertEqual(baseline.fail_count(3.0), 3)


class TestUndecidableCycles(_EngineCase):
    """ADV-2: 판정 불가 주기는 streak 과 prev 를 바꾸지 않는다."""

    def assertNeverBoth(self, got):
        self.assertFalse(any(BRIEF in c for c in got) and any(DOWN in c for c in got), got)

    def test_a_fail_undecidable_fail_success(self):
        _d, seen = self.drive("FNFS")
        got = self.first_hop(seen)
        self.assertEqual(got, [[], [], [], [BRIEF]])
        self.assertEqual(by_kind(seen[3], BRIEF).evidence["streak"], 2)

    def test_b_fail_fail_undecidable_success(self):
        _d, seen = self.drive("FFNS")
        got = self.first_hop(seen)
        self.assertEqual(got, [[], [], [], [BRIEF]])
        self.assertEqual(by_kind(seen[3], BRIEF).evidence["streak"], 2)

    def test_c_undecidable_in_a_three_cycle_outage(self):
        _d, seen = self.drive("FFNFS")
        got = self.first_hop(seen)
        self.assertEqual(got, [[], [], [], [DOWN], [BACK]])
        self.assertEqual(by_kind(seen[4], BACK).evidence["streak"], 3)
        self.assertNeverBoth(got)

    def test_d_undecidable_after_recovery_does_not_repeat(self):
        d, seen = self.drive("FFSNN")
        self.assertEqual(self.first_hop(seen), [[], [], [BRIEF], [], []])
        self.assertEqual(d.eng.state.get("gw_fail_streak_prev"), 2,
                         "prev 가 남아 있는 상태에서도 다시 나오지 않아야 한다")

    def test_e_icmp_gives_way_to_arp_mid_gap(self):
        d, _ = self.drive("")
        d.eng.state["icmp_fail_run"] = 17
        seen = d.run("FFF")    # ARP 정상, ICMP 실패
        self.assertEqual(d.eng.state.get("icmp_gw"), False)
        got = self.first_hop(seen)
        self.assertEqual(got, [[], [], [BRIEF]])
        f = by_kind(seen[2], BRIEF)
        self.assertEqual(f.evidence["streak"], 2)
        self.assertEqual(f.evidence["method"], "arp")
        self.assertEqual(kinds(seen[2]).count("GATEWAY_ICMP_SILENT"), 1)
        self.assertNeverBoth(got)


class TestInterruptedGaps(_EngineCase):
    """ADV-3: 연속 실패 중간에 링크·네트워크·시간이 끊기는 경우."""

    def test_a_link_absent_with_known_ssid_keeps_the_count(self):
        _d, seen = self.drive("FFAS", ssid=SSID)
        self.assertIn("LINK_ABSENT", kinds(seen[2]))
        self.assertEqual(self.first_hop(seen), [[], [], [], [BRIEF]])
        self.assertIsNone(by_kind(seen[3], BRIEF).attribution)

    def test_b_link_absent_without_ssid_resets(self):
        _d, seen = self.drive("FFAS")
        self.assertIn("LINK_ABSENT", kinds(seen[2]))
        self.assertEqual(self.first_hop(seen)[3], [])

    def test_c_network_change_resets(self):
        _d, seen = self.drive("FFMS")
        self.assertEqual(self.first_hop(seen)[2:], [[], []])

    def test_d_sleep_between_failure_and_success(self):
        _d, seen = self.drive("FFS", gaps={2: 60.0})
        self.assertEqual(self.first_hop(seen), [[], [], [BRIEF]])
        self.assertEqual(by_kind(seen[2], BRIEF).attribution, "sleep")

    def _restart(self, gap, keep_baseline=True):
        d, _ = self.drive("FF")
        d.eng.store.save_state(d.eng.state)
        if keep_baseline:
            d.eng._keep_baseline(d.eng.prev, d.wall)
        again = _Drive(_fresh_engine(self.dir), wall=d.wall)
        self.assertEqual(again.eng.state.get("gw_fail_streak"), 2)
        return again.run("S", gaps={0: gap})

    def test_e_restart_with_saved_baseline(self):
        seen = self._restart(5.0)
        self.assertEqual(self.first_hop(seen), [[BRIEF]])
        self.assertIsNone(by_kind(seen[0], BRIEF).attribution)

    def test_e_restart_after_a_long_stop(self):
        seen = self._restart(120.0)
        self.assertEqual(self.first_hop(seen), [[BRIEF]])
        self.assertEqual(by_kind(seen[0], BRIEF).attribution, "sleep")

    def test_e_restart_without_saved_baseline(self):
        seen = self._restart(5.0, keep_baseline=False)
        self.assertEqual(self.first_hop(seen), [[]])


if __name__ == "__main__":
    unittest.main()
