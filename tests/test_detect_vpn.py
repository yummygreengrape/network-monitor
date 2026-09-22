"""VPN 판정 — 상태 전환과 끊김.

원본 스크립트는 끊김 원인을 하나만 골랐다. 여기서는 한 번의 끊김이 품질과
보안 두 축에 따로 기록되고, "왜"는 분류가 아니라 근거로 붙는다.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from unittest import mock

from netmon import config as configmod
from netmon import messages
from netmon import messages as msg
from netmon import redact as redactmod
from netmon import vpn as vpnmod
from netmon.collect import link as first_hop
from netmon.collect.link import merge_probes, parse_ping
from netmon.engine import Engine
from netmon.detect import Context, attributions_for, network_key, run_all
from netmon.detect import vpn as vpn_rules
from netmon.model import PROBE_NOT_RUN, PROBE_TIMED_OUT
from tests.helpers import (ENDPOINT, ENDPOINT_REASON, GW_MAC, by_kind,
                           command_failed, endpoint_probe, kinds, obs,
                           vpn_state)

ON = {"detect.vpn": True, "detect.quality": True, "detect.l2": True,
      "detect.dhcp": True, "detect.dns": True, "detect.route": True,
      "detect.wifi": True}


PING_OUT = """PING 192.0.2.1 (192.0.2.1): 56 data bytes
%s
--- 192.0.2.1 ping statistics ---
%d packets transmitted, %d packets received, %.1f%% packet loss
"""


def one_command(o, sent=5, received=None, rtt=3.0):
    """`ping_count` 를 올려 둔 평소 주기의 첫 홉 관측.

    명령 하나로 여러 발을 보낸 결과다. 모양을 손으로 적지 않고 수집기의
    파서(`collect/link.parse_ping`)에 실제 ping 출력을 먹여 만든다 —
    합친 관측이 아니므로 `mode` 가 없다.

    `received` 를 줄이면 손실이 난 주기가 된다. **끊김 주기가 대개 그쪽이고**,
    그 결과에는 보낸 수가 남지 않는다(파서는 받은 수와 손실률만 읽는다).
    """
    received = sent if received is None else received
    lines = "\n".join("64 bytes from 192.0.2.1: icmp_seq=%d ttl=64 time=%.1f ms"
                       % (i, rtt) for i in range(received))
    loss = 100.0 * (sent - received) / sent if sent else 0.0
    result = parse_ping(PING_OUT % (lines, sent, received, loss))
    result["reachable"] = bool(result["replies"])
    o.data["link"]["results"]["gateway"] = result
    o.data["link"]["gateway_reachable"] = result["reachable"]
    # 수집기는 명령 수를 적는다. 평소 주기에는 몇 발을 보냈든 1 이다.
    o.data["link"]["first_hop_probes"] = 1
    return o


def unmeasured(o, empty=False):
    """첫 홉을 한 번도 재지 않은 주기.

    게이트웨이를 못 찾으면 수집기가 `results` 를 만들지 않고
    (collect/link.collect 의 "측정 대상 없음" 반환), 수집이 실패하면 블록
    자체가 비어 있다. `tests.helpers.obs()` 는 `gateway=None` 이어도
    `results["gateway"]` 를 채우므로 그 픽스처를 지나쳐 직접 만든다.
    """
    o.data["link"] = ({} if empty else
                      {"targets": {}, "note": "측정 대상 없음 (게이트웨이 미확인)"})
    return o


def burst(o, replies=(True, False, False), rtt=3.0, failed=()):
    """다발 주기의 첫 홉 관측.

    모양을 손으로 적지 않고 **실제 생산자**(collect/link.merge_probes)를
    그대로 쓴다. 첫 발이 응답한 3발 묶음이면 `reachable` 은 종전과 같이
    True 이고, 나머지 두 발의 손실은 증거에만 남는다.
    """
    probes = [{"reachable": bool(r), "rtt_ms": rtt if r else None,
               "replies": 1 if r else 0} for r in replies]
    # 명령 자체가 실패하거나 제한 시간을 넘긴 발. collect/link.collect 의
    # 예외 처리가 이 모양을 만든다 — 패킷이 나가지 않았는데 보낸 것으로 센다.
    for i in failed:
        probes[i] = {"reachable": False, "error": "timed out"}
    o.data["link"]["results"]["gateway"] = merge_probes(probes)
    o.data["link"]["gateway_reachable"] = bool(replies[0])
    o.data["link"]["first_hop_probes"] = len(probes)
    return o


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

    def test_healthy_first_hop_is_stated_not_turned_into_a_verdict(self):
        """첫 홉이 응답했다는 사실까지만 적는다.

        종전 문구는 같은 자리에서 "첫 홉은 정상 — 터널 경로 문제" 라고 고장
        위치를 지목했다. 1발 ICMP 가 돌아온 것으로는 로컬 구간과 터널
        상대편 구간을 나눌 수 없다.
        """
        prev = obs(vpn=vpn_state("connected"), icmp_ok=True)
        cur = obs(vpn=vpn_state("disconnected"), icmp_ok=True)
        f = by_kind(judge(prev, cur), "VPN_DISCONNECTED")
        self.assertIn(msg.WHY_FIRST_HOP_OK % msg.METHOD_ICMP, f.summary)
        self.assertNotIn("터널 경로", f.summary)
        self.assertIs(f.evidence["first_hop_alive"], True)

    def test_dead_first_hop_points_at_the_link(self):
        prev = obs(vpn=vpn_state("connected"), icmp_ok=True, gw_mac=GW_MAC)
        cur = obs(vpn=vpn_state("disconnected"), icmp_ok=False, gw_mac=None)
        f = by_kind(judge(prev, cur), "VPN_DISCONNECTED")
        self.assertIn(msg.WHY_LINK % msg.METHOD_ICMP, f.summary)
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
        # 초 그대로 적지 않는다 — 긴 끊김은 "604800초" 로 읽히면 다시 나눠야 한다.
        self.assertIn("7분 30초", f.summary)
        self.assertIn("6분 20초", f.summary)
        self.assertNotIn("450", f.summary)
        self.assertEqual(f.summary, msg.VPN_RECONNECTED
                         % ("warp", msg.VPN_SINCE_UNMEASURED
                            % ("00:00:00", "7분 30초", "6분 20초")))

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


class TestRenegotiationIsNotCalledADrop(unittest.TestCase):
    """공급자가 `connecting` 이라고 말한 것을 "연결 끊김" 으로 적지 않는다.

    2026-09-21 실측의 12건은 복구 직전 상태가 전부 `connecting` 이었다.
    다시 맺는 중인 것과 끊어진 것은 다른 사실이다. **판정 종류·등급과
    보호 상실 판정은 그대로 둔다** — 터널 밖으로 나간 사실은 같다.
    """

    def _drop(self, state):
        prev = obs(vpn=vpn_state("connected"), security="NONE")
        cur = obs(vpn=vpn_state(state), security="NONE")
        return judge(prev, cur)

    def test_connecting_is_worded_as_renegotiation(self):
        f = by_kind(self._drop("connecting"), "VPN_DISCONNECTED")
        self.assertTrue(f.summary.startswith(
            msg.VPN_RENEGOTIATING % ("warp", msg.WHY_FIRST_HOP_OK % msg.METHOD_ICMP)), f.summary)
        self.assertNotIn("연결 끊김", f.summary)
        self.assertEqual(f.evidence["provider_state"], "connecting")

    def test_a_real_disconnect_still_says_disconnected(self):
        f = by_kind(self._drop("disconnected"), "VPN_DISCONNECTED")
        self.assertTrue(f.summary.startswith(
            msg.VPN_DISCONNECTED % ("warp", msg.WHY_FIRST_HOP_OK % msg.METHOD_ICMP)), f.summary)
        self.assertEqual(f.evidence["provider_state"], "disconnected")

    def test_the_kind_and_severity_do_not_change(self):
        a = by_kind(self._drop("connecting"), "VPN_DISCONNECTED")
        b = by_kind(self._drop("disconnected"), "VPN_DISCONNECTED")
        self.assertEqual(a.kind, b.kind)
        self.assertEqual((a.axis, a.severity, a.confidence),
                         (b.axis, b.severity, b.confidence))

    def test_protection_loss_is_reported_exactly_as_before(self):
        a = by_kind(self._drop("connecting"), "VPN_PROTECTION_LOST")
        b = by_kind(self._drop("disconnected"), "VPN_PROTECTION_LOST")
        self.assertIsNotNone(a)
        self.assertEqual(a.severity, "medium")
        self.assertEqual((a.axis, a.severity, a.summary, a.attribution),
                         (b.axis, b.severity, b.summary, b.attribution))


class TestProviderReasonInTheSummary(unittest.TestCase):
    """사유는 고정 목록과 **정확히 일치할 때만** 요약문에 인용한다.

    사유 문자열에는 터널 엔드포인트의 공인 IP·포트가 들어 있고, 요약문은
    가리지 않은 채로 보고서에 나간다(redact 는 감싼 값만 바꾼다).
    """

    def _drop(self, reason):
        prev = obs(vpn=vpn_state("connected"))
        cur = obs(vpn=vpn_state("disconnected", reason=reason))
        return by_kind(judge(prev, cur), "VPN_DISCONNECTED")

    def test_an_exact_match_is_quoted(self):
        f = self._drop("No Network")
        self.assertIn(msg.VPN_PROVIDER_REASON % "No Network", f.summary)
        self.assertEqual(f.evidence["provider_reason"], "No Network")

    def test_anything_else_stays_in_the_evidence_only(self):
        cases = ["No Network detected", "no network", "NO NETWORK",
                 "Unable to reach 198.51.100.7:2408 (No Network)",
                 "handshake with 198.51.100.7:2408 timed out",
                 "", None]
        for reason in cases:
            with self.subTest(reason=reason):
                f = self._drop(reason)
                self.assertNotIn("공급자 사유", f.summary)
                self.assertNotIn("198.51.100", f.summary)
                if isinstance(reason, str) and reason:
                    self.assertNotIn(reason, f.summary)
                self.assertEqual(f.evidence["provider_reason"], reason)

    def test_surrounding_whitespace_does_not_defeat_the_list(self):
        f = self._drop("  No Network\n")
        self.assertIn(msg.VPN_PROVIDER_REASON % "No Network", f.summary)


class TestFirstHopEvidenceIsSingleOrBurst(unittest.TestCase):
    """1발인지 다발인지 문구와 근거에 드러낸다.

    다발 주기의 `reachable`·`rtt_ms` 는 첫 발 기준이라, 손실을 함께 적지
    않으면 3발 중 2발이 빠진 주기도 "첫 홉은 응답함" 으로만 남는다.
    """

    def _drop(self, cur):
        return by_kind(judge(obs(vpn=vpn_state("connected")), cur),
                       "VPN_DISCONNECTED")

    def test_a_plain_cycle_says_one_command_without_claiming_a_count(self):
        """다발이 아니라는 것만 적는다.

        보낸 발 수는 관측에 없다 — `collect/link.parse_ping` 은 받은 수와
        손실률만 읽는다. 기본 설정이 1발이라고 해서 요약문이 발 수를
        주장하면, `ping_count` 를 올려 둔 기계에서 그 문장이 거짓이 된다.
        """
        f = self._drop(obs(vpn=vpn_state("disconnected")))
        self.assertIn(msg.FIRST_HOP_EVIDENCE_ONE_COMMAND, f.summary)
        self.assertEqual(f.evidence["first_hop_probe_mode"], "single")
        self.assertNotIn("first_hop_sent", f.evidence)

    def test_a_burst_cycle_quotes_the_loss(self):
        cur = burst(obs(vpn=vpn_state("disconnected")))
        f = self._drop(cur)
        self.assertIn(msg.FIRST_HOP_EVIDENCE_BURST % (3, 1, 66.7), f.summary)
        self.assertNotIn(msg.FIRST_HOP_EVIDENCE_ONE_COMMAND, f.summary)
        self.assertEqual(f.evidence["first_hop_probe_mode"], "burst")
        self.assertEqual(f.evidence["first_hop_sent"], 3)
        self.assertEqual(f.evidence["first_hop_received"], 1)
        self.assertEqual(f.evidence["first_hop_loss_pct"], 66.7)
        # 판정이 읽는 값은 첫 발 기준 그대로다 (AC-1b).
        self.assertIs(f.evidence["first_hop_alive"], True)

    def test_a_burst_without_loss_still_says_it_was_a_burst(self):
        f = self._drop(burst(obs(vpn=vpn_state("disconnected")),
                             replies=(True, True, True)))
        self.assertIn(msg.FIRST_HOP_EVIDENCE_BURST % (3, 3, 0.0), f.summary)
        self.assertEqual(f.evidence["first_hop_loss_pct"], 0.0)

    def test_a_raised_ping_count_is_not_a_burst(self):
        """명령 하나로 5발을 보낸 평소 주기는 다발이 아니다.

        합친 관측이 아니라 `mode` 가 없고, 같은 순간의 동시 측정도 아니다.
        `first_hop_probes` 는 이때도 1 이다(명령 수).
        """
        cur = one_command(obs(vpn=vpn_state("disconnected")))
        self.assertEqual(cur.data["link"]["results"]["gateway"]["replies"], 5)
        self.assertNotIn("mode", cur.data["link"]["results"]["gateway"])
        f = self._drop(cur)
        self.assertEqual(f.evidence["first_hop_probe_mode"], "single")
        self.assertIn(msg.FIRST_HOP_EVIDENCE_ONE_COMMAND, f.summary)
        self.assertNotIn("first_hop_sent", f.evidence)

    def test_a_lossy_cycle_does_not_claim_how_many_probes_went_out(self):
        """손실이 난 주기에는 보낸 발 수를 알 수 없다 — 끊김 주기가 그쪽이다.

        `ping_count` 5 에 전부 손실이면 결과에 남는 것은 "받은 수 0,
        손실 100%" 뿐이라 1발이었는지 5발이었는지 구분할 수 없다. 그런
        주기에 "1발 ping" 이라고 적으면 없는 근거를 주장하는 것이 된다.
        """
        for sent, received in ((5, 0), (5, 1), (1, 0)):
            with self.subTest(sent=sent, received=received):
                f = self._drop(one_command(obs(vpn=vpn_state("disconnected")),
                                           sent=sent, received=received))
                self.assertEqual(f.evidence["first_hop_probe_mode"], "single")
                self.assertIn(msg.FIRST_HOP_EVIDENCE_ONE_COMMAND, f.summary)
                # 보낸 발 수를 주장하는 표현이 없다.
                self.assertNotIn("1발", f.summary)
                self.assertNotIn("%d발" % sent, f.summary)

    def test_the_single_branch_keeps_the_loss_in_the_evidence(self):
        """요약문이 발 수를 말하지 않으므로, 근거에서라도 읽을 수 있어야 한다."""
        f = self._drop(one_command(obs(vpn=vpn_state("disconnected")),
                                   sent=5, received=2))
        self.assertEqual(f.evidence["first_hop_received"], 2)
        self.assertEqual(f.evidence["first_hop_loss_pct"], 60.0)

    def test_a_cycle_that_measured_nothing_claims_no_probe(self):
        """보내지도 않은 1발을 증거로 적지 않는다."""
        for empty in (False, True):
            with self.subTest(empty=empty):
                f = self._drop(unmeasured(obs(vpn=vpn_state("disconnected")),
                                          empty=empty))
                self.assertEqual(f.evidence["first_hop_probe_mode"], "unmeasured")
                self.assertNotIn(msg.FIRST_HOP_EVIDENCE_ONE_COMMAND, f.summary)
                self.assertNotIn("1발", f.summary)
                self.assertNotIn("동시", f.summary)

    def test_only_the_first_probe_lost_does_not_accuse_the_local_leg(self):
        """첫 발만 빠진 주기를 "첫 홉 무응답" 이라고 적지 않는다.

        판정이 읽는 `reachable` 은 첫 발 기준이라(AC-1b) 이 주기의
        `first_hop_alive` 는 False 다. 그 값은 그대로 두고, 요약문만
        증거와 어긋나지 않게 유보한다.
        """
        f = self._drop(burst(obs(vpn=vpn_state("disconnected"), icmp_ok=False),
                             replies=(False, True, True)))
        self.assertIs(f.evidence["first_hop_alive"], False)
        self.assertEqual(f.evidence["first_hop_received"], 2)
        self.assertIn(msg.WHY_FIRST_HOP_MIXED % msg.METHOD_ICMP, f.summary)
        self.assertNotIn(msg.WHY_LINK % msg.METHOD_ICMP, f.summary)
        self.assertIn(msg.FIRST_HOP_EVIDENCE_BURST % (3, 2, 33.3), f.summary)

    def test_a_burst_that_lost_everything_still_names_the_local_leg(self):
        """증거가 어긋나지 않으면 종전 문장 그대로다."""
        f = self._drop(burst(obs(vpn=vpn_state("disconnected"), icmp_ok=False),
                             replies=(False, False, False)))
        self.assertIn(msg.WHY_LINK % msg.METHOD_ICMP, f.summary)
        self.assertEqual(f.evidence["first_hop_loss_pct"], 100.0)

    def test_a_partly_lost_burst_does_not_claim_the_first_hop_is_fine(self):
        f = self._drop(burst(obs(vpn=vpn_state("disconnected"))))
        self.assertIn(msg.WHY_FIRST_HOP_MIXED % msg.METHOD_ICMP, f.summary)
        self.assertNotIn(msg.WHY_FIRST_HOP_OK % msg.METHOD_ICMP, f.summary)

    def test_partial_icmp_on_an_arp_judged_network_is_not_called_erratic(self):
        """가드가 실제로 갈라내는 경로.

        ARP 로 판정하기로 정해진 망(`icmp_gw` False)은 게이트웨이가 ICMP 를
        걸러내거나 속도 제한을 건 곳이다. 거기서 3발 중 2발만 돌아온 것은
        장애의 증거가 아니다 — 가드를 지우면 `0 < 2 < 3` 이라 "엇갈림" 이
        정확한 설명("첫 홉은 응답함")을 밀어낸다.
        """
        cur = burst(obs(vpn=vpn_state("disconnected"), icmp_ok=False),
                    replies=(False, True, True))
        f = by_kind(judge(obs(vpn=vpn_state("connected")), cur,
                          state={"icmp_gw": False}), "VPN_DISCONNECTED")
        self.assertEqual(f.evidence["first_hop_method"], "arp")
        self.assertEqual(f.evidence["first_hop_received"], 2)
        self.assertNotIn(msg.WHY_FIRST_HOP_MIXED % msg.METHOD_ARP, f.summary)
        self.assertIn(msg.WHY_FIRST_HOP_OK % msg.METHOD_ARP, f.summary)

    def test_a_fully_lost_burst_on_an_arp_judged_network_names_its_basis(self):
        """ICMP 가 전부 빠졌는데 "첫 홉은 응답함" 이라고 적는 주기.

        ARP 로 판정하는 망에서는 실제로 그렇다. 판정 기준을 밝히지 않으면
        바로 뒤에 붙는 "응답 0발, 손실 100%" 와 모순으로만 읽힌다.
        전손실이라 `0 < received` 에 걸려 엇갈림 갈래로도 가지 않는다.
        """
        cur = burst(obs(vpn=vpn_state("disconnected"), icmp_ok=False),
                    replies=(False, False, False))
        f = by_kind(judge(obs(vpn=vpn_state("connected")), cur,
                          state={"icmp_gw": False}), "VPN_DISCONNECTED")
        self.assertIn(msg.WHY_FIRST_HOP_OK % msg.METHOD_ARP, f.summary)
        self.assertNotIn(msg.WHY_FIRST_HOP_MIXED % msg.METHOD_ARP, f.summary)
        # 무엇으로 판정했고 무엇을 쟀는지가 한 문장 안에 함께 있다.
        self.assertIn(msg.METHOD_ARP, f.summary)
        self.assertIn(msg.FIRST_HOP_EVIDENCE_BURST % (3, 0, 100.0), f.summary)
        self.assertEqual(f.evidence["first_hop_method"], "arp")

    def test_the_same_observation_reads_differently_by_judging_method(self):
        """같은 관측, 다른 판정 기준 — 요약문이 그 차이를 드러낸다."""
        def summary(icmp_gw):
            cur = burst(obs(vpn=vpn_state("disconnected"), icmp_ok=False),
                        replies=(False, True, True))
            return by_kind(judge(obs(vpn=vpn_state("connected")), cur,
                                 state={"icmp_gw": icmp_gw}),
                           "VPN_DISCONNECTED").summary
        self.assertIn(msg.METHOD_ARP, summary(False))
        self.assertIn(msg.METHOD_ICMP, summary(True))
        self.assertNotEqual(summary(False), summary(True))

    def _assert_method_labels_in_sync(self):
        """판정 방법의 **단일 출처**(netmon/liveness.METHOD_MESSAGES)와 견준다.

        여기에 리터럴 dict 를 적어 두면 판정 방법이 늘거나 이름이 바뀌어도
        이 테스트는 그대로 통과한다 — 드리프트를 잡으라고 둔 테스트가
        드리프트를 못 본다. 출처를 직접 읽어야 새 방법이 quality 쪽 이름표
        없이 들어오는 순간 걸린다.
        """
        from netmon import liveness
        from netmon.detect.quality import METHOD_LABEL
        self.assertEqual(
            {k: messages.get(v, "ko")
             for k, v in liveness.METHOD_MESSAGES.items()},
            METHOD_LABEL)

    def test_the_method_labels_match_the_quality_detector(self):
        """같은 기계의 같은 주기를 두 판정이 다른 말로 부르지 않는다."""
        self._assert_method_labels_in_sync()

    def test_a_judging_method_added_without_a_quality_label_is_caught(self):
        """드리프트가 실제로 걸리는지 확인한다.

        단일 출처에 방법이 하나 늘어난 상태를 만들면 동기화 단언이 깨져야
        한다. 리터럴 dict 로 되돌리면 출처를 보지 않으므로 이 상황을
        지나치고, 이 테스트가 실패한다.
        """
        from netmon import liveness
        with mock.patch.dict(liveness.METHOD_MESSAGES, {"fake": "METHOD_ICMP"}):
            with self.assertRaises(AssertionError):
                self._assert_method_labels_in_sync()

    def test_probes_that_failed_to_run_are_not_reported_as_network_loss(self):
        """다발의 "보낸 수" 는 띄운 명령 수다.

        명령이 실패하거나 제한 시간을 넘기면 패킷이 나가지 않았는데도 손실로
        셈된다. 그 손실률을 네트워크 손실처럼 적지 않고, 무엇이 실패했는지를
        근거에 남긴다.
        """
        cur = burst(obs(vpn=vpn_state("disconnected")),
                    replies=(True, False, False), failed=(1, 2))
        f = self._drop(cur)
        self.assertEqual(f.evidence["first_hop_errors"], ["timed out"])
        self.assertIn(msg.FIRST_HOP_EVIDENCE_BURST_FAILED % 1, f.summary)
        self.assertNotIn(msg.FIRST_HOP_EVIDENCE_BURST % (3, 1, 66.7), f.summary)
        # 셈 자체는 근거에 그대로 남는다 — 지우지 않고, 읽는 법만 밝힌다.
        self.assertEqual(f.evidence["first_hop_loss_pct"], 66.7)

    def test_both_branches_report_the_reply_count_under_one_key(self):
        """single 과 burst 가 같은 뜻을 같은 키로 적는다."""
        single = self._drop(one_command(obs(vpn=vpn_state("disconnected")),
                                        sent=5, received=2))
        multi = self._drop(burst(obs(vpn=vpn_state("disconnected"))))
        for f in (single, multi):
            self.assertIn("first_hop_received", f.evidence)
            self.assertNotIn("first_hop_replies", f.evidence)
        self.assertEqual(single.evidence["first_hop_received"], 2)
        self.assertEqual(multi.evidence["first_hop_received"], 1)


class TestAMeasurementThatNeverRanIsNotEvidence(unittest.TestCase):
    """나가지 않은 패킷은 구간을 지목하지 못한다.

    명령이 실행되지 못하면 수집기는 `reachable` 을 False 로 적는다
    (collect/link.collect). liveness 는 "무응답" 과 "재지 못함" 을 구분하지
    않으므로 `first_hop_alive` 는 False 로 나온다. 그 값은 그대로 두고,
    요약문만 재지 못한 사실에 맞춘다.
    """

    def _drop(self, cur, state=None):
        return by_kind(judge(obs(vpn=vpn_state("connected")), cur,
                             state=state or {"icmp_gw": True}),
                       "VPN_DISCONNECTED")

    def test_a_single_probe_that_failed_to_run_carries_its_error(self):
        """단수 키 `error` 를 다발과 같은 키로 근거에 싣는다."""
        f = self._drop(command_failed(obs(vpn=vpn_state("disconnected"))))
        self.assertEqual(f.evidence["first_hop_errors"], ["timed out"])
        self.assertEqual(f.evidence["first_hop_probe_mode"], "single")
        # 판정값 자체는 종전 그대로다 — 바꾸는 것은 문구뿐이다.
        self.assertIs(f.evidence["first_hop_alive"], False)

    def test_a_single_probe_that_failed_to_run_does_not_accuse_the_local_leg(self):
        f = self._drop(command_failed(obs(vpn=vpn_state("disconnected"))))
        self.assertIn(msg.WHY_FIRST_HOP_NOT_RUN, f.summary)
        self.assertNotIn(msg.WHY_LINK % msg.METHOD_ICMP, f.summary)
        self.assertIn(msg.FIRST_HOP_EVIDENCE_NOT_RUN, f.summary)
        self.assertNotIn(msg.FIRST_HOP_EVIDENCE_ONE_COMMAND, f.summary)

    def test_a_single_probe_that_did_run_still_names_the_local_leg(self):
        """가드가 넘치지 않는다 — 실제로 나갔는데 무응답인 주기는 그대로다."""
        f = self._drop(obs(vpn=vpn_state("disconnected"), icmp_ok=False,
                           gw_mac=None))
        self.assertIn(msg.WHY_LINK % msg.METHOD_ICMP, f.summary)
        self.assertNotIn(msg.WHY_FIRST_HOP_NOT_RUN, f.summary)

    def test_an_arp_judged_network_is_untouched_by_a_failed_ping(self):
        """ARP 로 판정하는 망의 `alive` 는 ping 결과에서 오지 않는다."""
        f = self._drop(command_failed(obs(vpn=vpn_state("disconnected"))),
                       state={"icmp_gw": False})
        self.assertEqual(f.evidence["first_hop_method"], "arp")
        self.assertIn(msg.WHY_FIRST_HOP_OK % msg.METHOD_ARP, f.summary)
        self.assertNotIn(msg.WHY_FIRST_HOP_NOT_RUN, f.summary)

    def test_a_burst_where_nothing_ran_is_not_called_partly_failed(self):
        """3발이 전부 실행 실패면 "일부" 가 아니다.

        실패 목록은 같은 문구끼리 합쳐지므로(collect/link.merge_probes) 몇
        발이 실패했는지 셀 수 없고, 응답이 0이면 나간 발이 있었는지조차
        모른다.
        """
        cur = burst(obs(vpn=vpn_state("disconnected"), icmp_ok=False),
                    replies=(False, False, False), failed=(0, 1, 2))
        f = self._drop(cur)
        self.assertEqual(f.evidence["first_hop_received"], 0)
        self.assertEqual(f.evidence["first_hop_errors"], ["timed out"])
        self.assertIn(msg.FIRST_HOP_EVIDENCE_BURST_NOT_RUN, f.summary)
        self.assertNotIn(msg.FIRST_HOP_EVIDENCE_BURST_FAILED % 0, f.summary)
        self.assertNotIn("일부", f.summary)

    def test_a_burst_where_nothing_ran_does_not_accuse_the_local_leg(self):
        cur = burst(obs(vpn=vpn_state("disconnected"), icmp_ok=False),
                    replies=(False, False, False), failed=(0, 1, 2))
        f = self._drop(cur)
        self.assertIn(msg.WHY_FIRST_HOP_NOT_RUN, f.summary)
        self.assertNotIn(msg.WHY_LINK % msg.METHOD_ICMP, f.summary)

    def test_a_burst_that_only_partly_failed_still_reads_as_before(self):
        """응답이 하나라도 있으면 나간 발이 있었다 — 유보 갈래가 아니다."""
        cur = burst(obs(vpn=vpn_state("disconnected")),
                    replies=(True, False, False), failed=(1, 2))
        f = self._drop(cur)
        self.assertIn(msg.FIRST_HOP_EVIDENCE_BURST_FAILED % 1, f.summary)
        self.assertNotIn(msg.FIRST_HOP_EVIDENCE_BURST_NOT_RUN, f.summary)
        self.assertNotIn(msg.WHY_FIRST_HOP_NOT_RUN, f.summary)


class TestNotRunAndTimedOutAreDifferentThings(unittest.TestCase):
    """실행되지 못한 주기와 끝나지 못한 주기를 뭉개지 않는다 (DEV-10, AC-10).

    전자는 패킷이 한 발도 나가지 않았고, 후자는 나갔을 수도 있는데 결과를
    받지 못했다. 어느 쪽도 "쟀다" 가 아니므로 구간을 지목하지 않지만,
    문구까지 같게 적으면 기록을 읽는 쪽이 둘을 구분할 수 없다.
    """

    def _drop(self, cur, state=None):
        return by_kind(judge(obs(vpn=vpn_state("connected")), cur,
                             state=state or {"icmp_gw": True}),
                       "VPN_DISCONNECTED")

    def _single(self, error):
        return self._drop(command_failed(obs(vpn=vpn_state("disconnected")),
                                         error=error))

    def _burst(self, probes):
        cur = obs(vpn=vpn_state("disconnected"), icmp_ok=False)
        # 모양은 실제 생산자에게 맡긴다 (collect/link.merge_probes).
        cur.data["link"]["results"]["gateway"] = merge_probes(probes)
        cur.data["link"]["gateway_reachable"] = bool(probes[0].get("reachable"))
        cur.data["link"]["first_hop_probes"] = len(probes)
        return self._drop(cur)

    def test_a_probe_that_ran_out_of_time_is_not_called_unrun(self):
        f = self._single(PROBE_TIMED_OUT)
        self.assertIn(msg.WHY_FIRST_HOP_TIMED_OUT, f.summary)
        self.assertIn(msg.FIRST_HOP_EVIDENCE_TIMED_OUT, f.summary)
        self.assertNotIn(msg.WHY_FIRST_HOP_NOT_RUN, f.summary)
        self.assertNotIn(msg.FIRST_HOP_EVIDENCE_NOT_RUN, f.summary)

    def test_a_probe_that_ran_out_of_time_still_names_no_leg(self):
        f = self._single(PROBE_TIMED_OUT)
        self.assertNotIn(msg.WHY_LINK % msg.METHOD_ICMP, f.summary)
        self.assertNotIn(msg.FIRST_HOP_EVIDENCE_ONE_COMMAND, f.summary)
        self.assertEqual(f.evidence["first_hop_errors"], [PROBE_TIMED_OUT])

    def test_a_probe_that_never_ran_keeps_its_own_words(self):
        f = self._single(PROBE_NOT_RUN)
        self.assertIn(msg.WHY_FIRST_HOP_NOT_RUN, f.summary)
        self.assertIn(msg.FIRST_HOP_EVIDENCE_NOT_RUN, f.summary)
        self.assertNotIn(msg.WHY_FIRST_HOP_TIMED_OUT, f.summary)
        self.assertNotIn(msg.FIRST_HOP_EVIDENCE_TIMED_OUT, f.summary)

    def test_an_unknown_failure_reads_as_before(self):
        """수집기의 future 예외 갈래가 남기는 문구는 종전 그대로다."""
        f = self._single("TimeoutError")
        self.assertIn(msg.WHY_FIRST_HOP_NOT_RUN, f.summary)
        self.assertNotIn(msg.WHY_FIRST_HOP_TIMED_OUT, f.summary)

    def test_a_mixed_burst_makes_the_weaker_claim(self):
        """하나라도 실행되지 못했으면 "전부 시간만 넘겼다" 고 적지 않는다."""
        f = self._burst([{"reachable": False, "error": PROBE_TIMED_OUT},
                         {"reachable": False, "error": PROBE_NOT_RUN},
                         {"reachable": False, "error": PROBE_TIMED_OUT}])
        self.assertEqual(sorted(f.evidence["first_hop_errors"]),
                         sorted([PROBE_TIMED_OUT, PROBE_NOT_RUN]))
        self.assertIn(msg.FIRST_HOP_EVIDENCE_BURST_NOT_RUN, f.summary)
        self.assertNotIn(msg.FIRST_HOP_EVIDENCE_BURST_TIMED_OUT_NONE, f.summary)
        self.assertIn(msg.WHY_FIRST_HOP_NOT_RUN, f.summary)

    def test_a_burst_that_only_ran_out_of_time_says_so(self):
        f = self._burst([{"reachable": False, "error": PROBE_TIMED_OUT}] * 3)
        self.assertIn(msg.FIRST_HOP_EVIDENCE_BURST_TIMED_OUT_NONE, f.summary)
        self.assertNotIn(msg.FIRST_HOP_EVIDENCE_BURST_NOT_RUN, f.summary)
        self.assertIn(msg.WHY_FIRST_HOP_TIMED_OUT, f.summary)
        self.assertNotIn(msg.WHY_LINK % msg.METHOD_ICMP, f.summary)
        self.assertNotIn("일부", f.summary)

    def test_a_partly_timed_out_burst_keeps_the_answer_count(self):
        """응답이 하나라도 있으면 나간 발이 있었다 — 손실률만 못 읽는다."""
        f = self._burst([{"reachable": True, "rtt_ms": 3.0, "replies": 1},
                         {"reachable": False, "error": PROBE_TIMED_OUT},
                         {"reachable": False, "error": PROBE_TIMED_OUT}])
        self.assertIn(msg.FIRST_HOP_EVIDENCE_BURST_TIMED_OUT % 1, f.summary)
        self.assertNotIn(msg.FIRST_HOP_EVIDENCE_BURST_FAILED % 1, f.summary)
        self.assertNotIn(msg.WHY_FIRST_HOP_TIMED_OUT, f.summary)

    def test_both_kinds_are_still_kept_out_of_the_english_summary_too(self):
        """두 문구가 en 카탈로그에도 있어야 요약문이 갈린다."""
        for key in ("WHY_FIRST_HOP_TIMED_OUT", "FIRST_HOP_EVIDENCE_TIMED_OUT",
                    "FIRST_HOP_EVIDENCE_BURST_TIMED_OUT",
                    "FIRST_HOP_EVIDENCE_BURST_TIMED_OUT_NONE"):
            for code in ("ko", "en"):
                self.assertTrue(messages.get(key, code).strip(), (key, code))


class TestAnEndpointThatWasNotMeasuredHasNoResult(unittest.TestCase):
    """나가지 못한 엔드포인트 측정이 도달 실패로 기록되지 않는다 (DEV-10).

    `ping()` 이 실행 실패를 `error` 로 남기므로 엔드포인트 결과에도 그 키가
    붙는다. 덮였는지 **수집기를 실제로 돌려** 확인한다 — 손으로 적은 모양은
    수집기가 바뀌면 같이 틀어진다.
    """

    def _cycle(self, real_argv):
        from netmon import util
        from netmon.collect import link as first_hop

        def fake(argv, timeout=None, stdin=""):
            return util.run(real_argv)

        with mock.patch.object(first_hop, "run", fake):
            block = first_hop.collect({"gateway": "192.0.2.1",
                                       "allow_tunnel_probe": True,
                                       "tunnel_endpoint": ENDPOINT})
        prev = obs(vpn=vpn_state("connected"), security="WPA2_PSK")
        cur = obs(ts="2026-01-01T00:00:15Z",
                  vpn=vpn_state("disconnected", reason=ENDPOINT_REASON),
                  security="WPA2_PSK")
        cur.data["link"] = block
        return by_kind(judge(prev, cur), "VPN_DISCONNECTED")

    def test_a_cycle_whose_ping_could_not_run(self):
        f = self._cycle(["netmon-no-such-command-for-tests"])
        # 엔드포인트: 도달성은 적지 않고 실패만 남는다.
        self.assertNotIn("tunnel_endpoint_reachable", f.evidence)
        self.assertEqual(f.evidence["tunnel_endpoint_error"], PROBE_NOT_RUN)
        self.assertEqual(f.evidence["tunnel_endpoint"], {"id": "ipv4", "v": ENDPOINT})
        # 첫 홉: 같은 실패가 근거로 실리고 구간을 지목하지 않는다.
        self.assertEqual(f.evidence["first_hop_errors"], [PROBE_NOT_RUN])
        self.assertIn(msg.WHY_FIRST_HOP_NOT_RUN, f.summary)
        self.assertNotIn(msg.WHY_LINK % msg.METHOD_ICMP, f.summary)
        self.assertNotIn(ENDPOINT, f.summary)

    def test_a_measured_cycle_still_records_reachability(self):
        """가드가 넘치지 않는다 — 실제로 나간 주기는 종전대로 적는다."""
        f = self._cycle(["true"])
        self.assertIn("tunnel_endpoint_reachable", f.evidence)
        self.assertFalse(f.evidence["tunnel_endpoint_reachable"])
        self.assertNotIn("tunnel_endpoint_error", f.evidence)


class TestTheKindSetIsFrozen(unittest.TestCase):
    """이 판정기가 내는 종류 집합. 기준 커밋(a502aeb)과 같다.

    새 종류를 늘리면 한·영 문구와 문서 표가 함께 따라와야 하므로
    (AC-11), 늘어났다는 사실 자체를 여기서 먼저 걸리게 한다.
    """

    KINDS = {"VPN_DISCONNECTED", "VPN_PROTECTION_LOST", "VPN_RECONNECTED",
             "VPN_STATE_CHANGED", "VPN_STATE_UNKNOWN", "VPN_TUNNEL_OFF",
             "VPN_TUNNEL_ON"}

    def test_the_module_emits_only_these_kinds(self):
        import io
        import re
        with io.open(vpn_rules.__file__, encoding="utf-8") as fh:
            src = fh.read()
        self.assertEqual(set(re.findall(r'kind="([A-Z_]+)"', src)), self.KINDS)

    def test_no_new_security_kind_was_added(self):
        self.assertEqual({k for k in self.KINDS if "PROTECTION" in k or "TUNNEL_OFF" in k},
                         {"VPN_PROTECTION_LOST", "VPN_TUNNEL_OFF"})


class TestDownTimeReadsAsTime(unittest.TestCase):
    """끊긴 시간을 초 단위 숫자로만 적지 않는다 (AC-8 의 표기 부분).

    증거 필드(`down_seconds`·`unmeasured_seconds`)는 초 단위 숫자 그대로다.
    바뀌는 것은 요약문뿐이다.
    """

    def _reconnected(self, prev_ts, cur_ts, since, unmeasured):
        prev = obs(ts=prev_ts, vpn=vpn_state("disconnected"))
        cur = obs(ts=cur_ts, vpn=vpn_state("connected"))
        return by_kind(judge(prev, cur, state={
            "icmp_gw": True, "vpn_down_since": {"warp": since},
            "vpn_down_unmeasured": {"warp": unmeasured}}), "VPN_RECONNECTED")

    def test_a_long_outage_is_not_printed_in_bare_seconds(self):
        f = self._reconnected("2026-01-07T23:59:55Z", "2026-01-08T00:00:00Z",
                              "2026-01-01T00:00:00Z", 3700.0)
        self.assertEqual(f.evidence["down_seconds"], 604800.0)
        self.assertEqual(f.evidence["unmeasured_seconds"], 3700.0)
        self.assertIn("7일", f.summary)
        self.assertIn("1시간 1분", f.summary)
        self.assertNotIn("604800", f.summary)

    def test_a_sub_second_gap_is_not_rounded_away_to_zero(self):
        """반올림해서 "0초" 라고 적으면 있었던 공백이 없었던 것이 된다."""
        f = self._reconnected("2026-01-01T00:00:05Z", "2026-01-01T00:00:10Z",
                              "2026-01-01T00:00:05Z", 0.4)
        self.assertEqual(f.evidence["unmeasured_seconds"], 0.4)
        self.assertIn(msg.DUR_UNDER_SECOND, f.summary)
        self.assertNotIn("0초", f.summary)
        self.assertIn("5초 끊김", f.summary)


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


# --- 터널 엔드포인트 (AC-4, AC-4b, AC-4c, AC-5, AC-6 의 증거 부분) ---

CONTROL_JUNK = "\x1b[31mNo\tNetwork\r\n\u202e via 198.51.100.7:2408\x00"


class TestPickingTheEndpointAddress(unittest.TestCase):
    """사유 문자열에서 주소 하나 고르기 (QA-20, ADV-1, AC-4b).

    문자열을 만드는 쪽이 대상 주소를 정한다. 고르지 못하면 관측하지 않는다.
    """

    def pick(self, reason):
        return vpnmod.endpoint_from_reason(reason)

    def test_ipv4_is_picked_and_the_port_is_dropped(self):
        self.assertEqual(self.pick(ENDPOINT_REASON), ENDPOINT)

    def test_ipv4_wins_when_both_families_are_present(self):
        self.assertEqual(self.pick("via 198.51.100.7:2408 (2001:db8::1)"), ENDPOINT)
        self.assertEqual(self.pick("via [2001:db8::1]:2408 then 198.51.100.7"), ENDPOINT)

    def test_ipv6_only_is_not_measured_in_this_scope(self):
        self.assertIsNone(self.pick("connected to [2001:db8::1]:2408"))
        self.assertIsNone(self.pick("via ::ffff:198.51.100.7"))

    def test_no_address_means_no_measurement(self):
        for reason in (None, "", "   ", "No Network", "error 500", 7, ["198.51.100.7"],
                       {"addr": "198.51.100.7"}):
            self.assertIsNone(self.pick(reason), reason)

    def test_a_broken_piece_is_not_recorded_as_an_address(self):
        """주소 모양의 다른 숫자를 주소로 적지 않는다."""
        self.assertIsNone(self.pick("build 198.51.100.7.9"))
        self.assertIsNone(self.pick("version 999.1.2.3"))
        # 뒤에 진짜 주소가 있으면 그쪽을 고른다. 잘린 조각은 버린다.
        self.assertEqual(self.pick("version 999.1.2.3 via 198.51.100.7"), ENDPOINT)

    def test_the_first_address_is_the_only_target(self):
        self.assertEqual(self.pick("198.51.100.7 203.0.113.9 192.0.2.7"), ENDPOINT)

    def test_control_characters_do_not_raise_and_do_not_come_back(self):
        """제어문자·ANSI·개행·RTL 이 섞여도 예외 없이 끝난다 (ADV-1).

        돌려주는 값은 `ipaddress` 가 해석한 주소뿐이라, 그런 문자가 증거로
        실려 나갈 자리가 없다.
        """
        got = self.pick(CONTROL_JUNK)
        self.assertEqual(got, ENDPOINT)
        self.assertTrue(all(ch.isprintable() for ch in got), repr(got))
        self.assertIsNone(self.pick("\x1b[31m\x00\u202e no address\r\n"))

    def test_a_very_long_string_is_bounded(self):
        """훑는 길이와 후보 수를 제한한다. 제한 밖의 주소는 고르지 않는다."""
        self.assertIsNone(self.pick("x" * 600 + " 198.51.100.7"))
        self.assertEqual(self.pick("x" * 10 + " 198.51.100.7"), ENDPOINT)
        # 주소 모양의 숫자를 잔뜩 앞세워 훑기를 길게 끌지 못한다.
        junk = "999.1.2.3 " * (vpnmod.REASON_MAX_CANDIDATES + 1)
        self.assertIsNone(self.pick(junk + "198.51.100.7"))


class TestOnlyPublicUnicastIsProbed(unittest.TestCase):
    """대상 주소를 외부 문자열이 정한다 (ADV-6, AC-4b).

    루프백·링크로컬·멀티캐스트·브로드캐스트·사설 대역은 고르지 않는다.
    기록도 하지 않는다 — 돌려주는 값이 없으면 관측 항목 자체가 생기지 않는다.
    """

    BLOCKED = ("127.0.0.1", "10.0.0.0", "192.168.0.0", "172.16.0.0",
               "100.64.0.0", "169.254.0.0", "224.0.0.0", "255.255.255.255",
               "0.0.0.0", "240.0.0.0")

    def test_blocked_ranges_are_not_picked(self):
        for addr in self.BLOCKED:
            self.assertFalse(vpnmod.public_unicast(addr), addr)
            self.assertIsNone(vpnmod.endpoint_from_reason("via %s:2408" % addr), addr)

    def test_ipv6_and_junk_are_not_unicast_targets(self):
        for addr in ("::1", "fe80::1", "ff02::1", "2001:db8::1", "", None,
                     "not-an-address", "198.51.100", "198.51.100.256"):
            self.assertFalse(vpnmod.public_unicast(addr), addr)

    def test_a_public_address_is_allowed_even_if_we_cannot_vouch_for_it(self):
        """제3자 공인 주소인지 아닌지는 이 도구가 가릴 수 없다.

        공급자가 알려 준 상대편이 맞는지 확인할 방법이 없으므로, 공인
        유니캐스트라는 사실까지만 확인하고 보낸다.
        """
        self.assertTrue(vpnmod.public_unicast(ENDPOINT))
        self.assertTrue(vpnmod.public_unicast("203.0.113.9"))

    def test_a_private_address_in_front_does_not_get_a_second_chance(self):
        """사설 주소 뒤에 공인 주소를 붙여 대상을 고르게 하지 못한다."""
        self.assertIsNone(vpnmod.endpoint_from_reason("10.0.0.0 via 198.51.100.7"))


class TestWhichCycleGetsAnAddress(unittest.TestCase):
    """직전 주기의 VPN 이 connected 가 아니었을 때만 (QA-19, QA-22, AC-4)."""

    def test_a_connected_provider_is_not_probed(self):
        block = vpn_state("connected", reason=ENDPOINT_REASON)
        self.assertIsNone(vpnmod.tunnel_endpoint(block))

    def test_a_disconnected_provider_gives_the_address(self):
        block = vpn_state("disconnected", reason=ENDPOINT_REASON)
        self.assertEqual(vpnmod.tunnel_endpoint(block), ENDPOINT)

    def test_renegotiating_counts_too(self):
        block = vpn_state("connecting", reason=ENDPOINT_REASON)
        self.assertEqual(vpnmod.tunnel_endpoint(block), ENDPOINT)

    def test_a_connected_providers_address_is_not_borrowed(self):
        """둘 중 끊긴 쪽의 주소만 쓴다."""
        block = dict(vpn_state("connected", reason="via 203.0.113.9:2408",
                               provider="tailscale"))
        block.update(vpn_state("disconnected", reason=ENDPOINT_REASON, provider="warp"))
        self.assertEqual(vpnmod.tunnel_endpoint(block), ENDPOINT)

    def test_a_missing_or_broken_block_is_not_an_address(self):
        for block in (None, {}, [], "warp", {"warp": None}, {"warp": "disconnected"},
                      vpn_state("disconnected", reason=None)):
            self.assertIsNone(vpnmod.tunnel_endpoint(block), block)

    def test_unknown_is_not_a_trigger(self):
        """조회가 실패했을 때의 사유는 stderr 문자열이다 (AC-4 수정분).

        `warp-cli` 호출이 실패하면 `reason` 에 stderr 가 들어가고
        (`netmon/vpn/__init__.py` 의 `status` 들), 거기 섞인 주소는 터널
        상대편이 아니다. 끝나는 조건도 없어서 설치만 하고 꺼 둔 공급자나
        조회가 계속 실패하는 공급자가 있으면 무한히 나간다.
        """
        block = vpn_state("unknown", reason=ENDPOINT_REASON)
        self.assertIsNone(vpnmod.tunnel_endpoint(block))

    def test_only_two_states_send(self):
        """보내는 상태는 disconnected 와 connecting 둘뿐이다."""
        self.assertEqual(vpnmod.PROBE_STATES, ("disconnected", "connecting"))
        for state in ("disconnected", "connecting"):
            self.assertEqual(
                vpnmod.tunnel_endpoint(vpn_state(state, reason=ENDPOINT_REASON)),
                ENDPOINT, state)
        for state in ("connected", "unknown", "", None, "disconnecting"):
            self.assertIsNone(
                vpnmod.tunnel_endpoint(vpn_state(state, reason=ENDPOINT_REASON)),
                state)

    def test_an_unknown_provider_does_not_lend_its_address_to_another(self):
        """조회 실패한 공급자의 문자열이 다른 공급자 때문에 딸려 나가지 않는다."""
        block = dict(vpn_state("unknown", reason=ENDPOINT_REASON, provider="warp"))
        block.update(vpn_state("connected", reason=None, provider="tailscale"))
        self.assertIsNone(vpnmod.tunnel_endpoint(block))


class TestTheProbeWindow(unittest.TestCase):
    """상한을 세는 단위 — **공급자 하나의 끊김 하나** (AC-4 수정분).

    처음에는 "아무 공급자나 비connected 면 창이 열려 있다" 로 셌는데, 그러면
    `MacOSNative` 처럼 담당할 서비스가 없어 늘 `unknown` 을 돌려주는 공급자가
    창을 영영 열어 둔다(`vpn/__init__.py` 의 "직접 담당할 서비스 없음").
    `scutil` 은 모든 맥에 있어 기본 설정에서 그 공급자가 늘 목록에 들므로,
    상한이 "한 끊김" 이 아니라 프로세스 수명당 예산이 됐다 — 첫 12발을 쓰고
    나면 그 뒤의 어떤 끊김에서도 한 발도 나가지 않는다 (검수 1차 지적).
    """

    def _rec(self, shots=3, capped=False):
        return {"warp": {"shots": shots, "capped": capped}}

    def test_a_not_connected_provider_keeps_its_record(self):
        for state in ("disconnected", "connecting"):
            self.assertEqual(
                vpnmod.carry_probe_counts(self._rec(), vpn_state(state)),
                {"warp": {"shots": 3, "capped": False}}, state)

    def test_connected_drops_its_record(self):
        self.assertEqual(
            vpnmod.carry_probe_counts(self._rec(), vpn_state("connected")), {})

    def test_unknown_keeps_a_record_but_never_makes_one(self):
        """모른다는 것은 끊김이 끝났다는 뜻도, 시작됐다는 뜻도 아니다.

        닫는 것으로 보면 조회가 간헐적으로 실패하는 동안 상한이 되살아나
        한 끊김에 12발보다 많이 나간다. 여는 것으로 보면 늘 `unknown` 인
        공급자가 창을 영영 열어 둔다. 그 주기에 보내지도 않는다.
        """
        block = vpn_state("unknown", reason=ENDPOINT_REASON)
        self.assertEqual(vpnmod.carry_probe_counts(self._rec(), block),
                         {"warp": {"shots": 3, "capped": False}})
        self.assertEqual(vpnmod.carry_probe_counts({}, block), {})
        self.assertIsNone(vpnmod.tunnel_endpoint(block))

    def test_an_always_unknown_provider_does_not_hold_another_open(self):
        """늘 `unknown` 인 공급자가 있어도 다른 공급자의 끊김은 제때 끝난다.

        이것이 상한을 공급자별로 세는 까닭이다 (검수 1차 지적).
        """
        block = {"macos": {"provider": "macos", "state": "unknown",
                           "reason": "직접 담당할 서비스 없음 (전용 공급자가 처리)"},
                 "warp": {"provider": "warp", "state": "connected", "reason": None}}
        self.assertEqual(vpnmod.carry_probe_counts(self._rec(), block), {})

    def test_a_provider_missing_from_the_block_keeps_its_record(self):
        """관측하지 못한 주기를 "연결됐다" 로 읽지 않는다."""
        for block in (None, {}, [], "warp", {"warp": None}):
            self.assertEqual(vpnmod.carry_probe_counts(self._rec(), block),
                             {"warp": {"shots": 3, "capped": False}}, block)

    def test_the_capped_mark_is_carried(self):
        self.assertEqual(
            vpnmod.carry_probe_counts(self._rec(shots=12, capped=True),
                                      vpn_state("disconnected")),
            {"warp": {"shots": 12, "capped": True}})

    def test_a_broken_record_counts_as_no_record(self):
        """옛 판의 정수 하나를 포함해, 모양이 다르면 0 부터 센다."""
        block = vpn_state("disconnected", reason=ENDPOINT_REASON)
        for raw in (None, 12, "많이", True, [], {"warp": 12}, {"warp": None},
                    {"warp": {"shots": -1}}, {"warp": {"shots": "많이"}},
                    {"warp": {"shots": True}}, {"warp": {}}):
            self.assertEqual(vpnmod.carry_probe_counts(raw, block), {}, raw)


class TestTheOutageCarriesItsEndpointTally(unittest.TestCase):
    """복구 판정의 증거에 그 끊김의 엔드포인트 측정 요약이 실린다.

    상한에 닿는 것은 끊김이 **이어지는** 주기에 일어나는데, 끊김 판정은
    connected → 그 밖 **전환 주기**에만 난다. 그래서 `tunnel_endpoint_capped`
    는 관측 표본에만 남고 이벤트에는 실리지 않아, 이벤트만 읽는 쪽에서는
    "12발을 다 쓰고 멈춘 끊김" 과 "한 발도 재지 않은 끊김" 이 구분되지
    않았다 (검수 1차 지적). 새 판정 종류도 새 문구도 만들지 않고, 이미
    `down_seconds`·`unmeasured_seconds` 를 싣고 있는 자리에 값으로 남긴다.
    """

    def _reconnect(self, probes):
        prev = obs(ts="2026-01-01T00:07:25Z", vpn=vpn_state("disconnected"))
        cur = obs(ts="2026-01-01T00:07:30Z", vpn=vpn_state("connected"))
        state = {"icmp_gw": True,
                 "vpn_down_since": {"warp": "2026-01-01T00:00:00Z"}}
        if probes is not None:
            state[vpnmod.ENDPOINT_PROBES_KEY] = probes
        return by_kind(judge(prev, cur, state=state), "VPN_RECONNECTED")

    def test_a_capped_outage_says_so_with_values(self):
        f = self._reconnect({"warp": {"shots": 12, "capped": True}})
        self.assertEqual(f.evidence["tunnel_endpoint_shots"], 12)
        self.assertTrue(f.evidence["tunnel_endpoint_cap_reached"])
        # 요약문은 그대로다 — 새 문구를 만들지 않는다.
        self.assertEqual(f.summary, msg.VPN_RECONNECTED
                         % ("warp", msg.VPN_SINCE % "00:00:00"))

    def test_an_outage_that_stopped_early_is_not_read_as_capped(self):
        f = self._reconnect({"warp": {"shots": 3, "capped": False}})
        self.assertEqual(f.evidence["tunnel_endpoint_shots"], 3)
        self.assertFalse(f.evidence["tunnel_endpoint_cap_reached"])

    def test_no_record_is_not_written_as_zero(self):
        """기록이 없는 것과 "0발 나갔다" 는 다르다.

        기능이 꺼져 있었거나 주소를 한 번도 못 얻었을 수 있다. 없는 측정을
        0 으로 적으면 관측하지 않은 것을 관측한 것처럼 적는 것이 된다.
        """
        for probes in (None, {}, {"tailscale": {"shots": 4}}, 12, "많이",
                       {"warp": 12}, {"warp": {"shots": "많이"}},
                       {"warp": {"shots": True}}):
            f = self._reconnect(probes)
            self.assertNotIn("tunnel_endpoint_shots", f.evidence, probes)
            self.assertNotIn("tunnel_endpoint_cap_reached", f.evidence, probes)

    def test_the_other_evidence_is_untouched(self):
        f = self._reconnect({"warp": {"shots": 12, "capped": True}})
        self.assertEqual(f.evidence["down_since"], "2026-01-01T00:00:00Z")
        self.assertEqual(f.evidence["down_seconds"], 450.0)
        self.assertEqual(f.evidence["unmeasured_seconds"], 0.0)
        self.assertEqual(f.evidence["prev_state"], "disconnected")


class TestTunnelEndpointEvidence(unittest.TestCase):
    """끊김 판정의 증거에 실린다 (QA-6, QA-7, AC-5, AC-6).

    끊김 판정은 connected → 그 밖 전환에서 나고, 주소는 직전 주기 것이라
    보통 한 주기 늦는다(AC-4c). 둘이 만나는 실측 모양은 "링크가 없어 판정을
    건너뛴 주기가 사이에 끼어 있는" 경우다 — 그동안 판정의 비교 기준(prev)은
    마지막 완전 관측(connected)에 머물러 있고, 엔드포인트 주소는 그 사이
    주기의 사유에서 이미 얻어 둔다.
    """

    def _drop(self, **kw):
        prev = obs(vpn=vpn_state("connected"), security="WPA2_PSK")
        cur = obs(ts="2026-01-01T00:00:15Z",
                  vpn=vpn_state("disconnected", reason=ENDPOINT_REASON),
                  security="WPA2_PSK")
        endpoint_probe(cur, **kw)
        return by_kind(judge(prev, cur), "VPN_DISCONNECTED")

    def test_the_address_is_wrapped_and_the_result_is_carried(self):
        f = self._drop(rtt=25.0)
        self.assertEqual(f.evidence["tunnel_endpoint"], {"id": "ipv4", "v": ENDPOINT})
        self.assertTrue(f.evidence["tunnel_endpoint_reachable"])
        self.assertEqual(f.evidence["tunnel_endpoint_rtt_ms"], 25.0)
        self.assertEqual(f.evidence["provider_reason"], ENDPOINT_REASON)

    def test_no_answer_is_recorded_without_calling_it_blocked(self):
        f = self._drop(reachable=False)
        self.assertFalse(f.evidence["tunnel_endpoint_reachable"])
        self.assertNotIn("tunnel_endpoint_rtt_ms", f.evidence)

    def test_a_probe_that_never_ran_carries_only_the_error_kind(self):
        """실패한 주기는 **도달성을 적지 않는다** (DEV-10).

        종전에는 같은 결과에서 `tunnel_endpoint_reachable: False` 도 함께
        만들었다. 그 False 는 "응답이 없었다" 가 아니라 "아는 바가 없다"
        인데, 값으로 적으면 나가지도 않은 패킷의 무응답이 도달 실패로
        기록된다.
        """
        f = self._drop(error="TimeoutError")
        self.assertEqual(f.evidence["tunnel_endpoint_error"], "TimeoutError")
        self.assertNotIn("tunnel_endpoint_reachable", f.evidence)
        # 대상 주소는 그대로 남는다 — 무엇을 향해 보내려 했는지는 사실이다.
        self.assertEqual(f.evidence["tunnel_endpoint"], {"id": "ipv4", "v": ENDPOINT})

    def test_reaching_the_cap_is_recorded_without_claiming_a_result(self):
        """상한에 닿아 보내지 않은 주기는 그 사실만 남는다 (AC-4 수정분).

        보내지 않았으므로 도달성은 적지 않는다. "재지 않은 주기" 와
        구분되지 않으면 기록을 읽는 쪽이 안 보낸 이유를 알 수 없다.
        """
        prev = obs(vpn=vpn_state("connected"), security="WPA2_PSK")
        cur = obs(ts="2026-01-01T00:00:15Z",
                  vpn=vpn_state("disconnected", reason=ENDPOINT_REASON),
                  security="WPA2_PSK")
        cur.data["link"]["tunnel_endpoint_capped"] = True
        f = by_kind(judge(prev, cur), "VPN_DISCONNECTED")
        self.assertTrue(f.evidence["tunnel_endpoint_capped"])
        self.assertNotIn("tunnel_endpoint_reachable", f.evidence)
        self.assertNotIn("tunnel_endpoint_error", f.evidence)
        self.assertNotIn(ENDPOINT, f.summary)

    def test_a_measured_cycle_is_not_marked_as_capped(self):
        f = self._drop()
        self.assertNotIn("tunnel_endpoint_capped", f.evidence)

    def test_an_unmeasured_cycle_makes_no_keys_at_all(self):
        """동의가 없거나 주소를 몰랐던 주기를 '무응답' 으로 읽히게 두지 않는다."""
        prev = obs(vpn=vpn_state("connected"), security="WPA2_PSK")
        cur = obs(ts="2026-01-01T00:00:05Z",
                  vpn=vpn_state("disconnected", reason=ENDPOINT_REASON),
                  security="WPA2_PSK")
        f = by_kind(judge(prev, cur), "VPN_DISCONNECTED")
        self.assertFalse([k for k in f.evidence if k.startswith("tunnel_endpoint")],
                         f.evidence)

    def test_the_summary_never_carries_the_address(self):
        """요약문은 가리지 않은 채로 화면·보고서에 나간다 (AC-6)."""
        f = self._drop()
        self.assertNotIn(ENDPOINT, f.summary)
        self.assertNotIn("2408", f.summary)
        self.assertNotIn(ENDPOINT_REASON, f.summary)

    def test_a_hostile_reason_does_not_reach_the_summary(self):
        """제어문자가 섞인 사유도 요약문에 인용되지 않는다 (ADV-1, ADV-2)."""
        prev = obs(vpn=vpn_state("connected"), security="WPA2_PSK")
        cur = obs(ts="2026-01-01T00:00:15Z",
                  vpn=vpn_state("disconnected", reason=CONTROL_JUNK),
                  security="WPA2_PSK")
        endpoint_probe(cur)
        f = by_kind(judge(prev, cur), "VPN_DISCONNECTED")
        self.assertTrue(all(ch.isprintable() or ch == " " for ch in f.summary),
                        repr(f.summary))
        self.assertNotIn(ENDPOINT, f.summary)
        # 원문은 종전처럼 로컬 기록(증거)에 그대로 남는다 (AC-5).
        self.assertEqual(f.evidence["provider_reason"], CONTROL_JUNK)

    def test_the_collectors_own_output_fits_the_evidence(self):
        """손으로 적은 모양이 아니라 수집기가 만든 관측으로 확인한다.

        `collect/link.collect` 를 가짜 `run` 으로 돌려(패킷은 나가지 않는다)
        그 결과를 그대로 판정에 먹인다. 수집기의 키 이름이 바뀌면 여기서
        깨진다.
        """
        from unittest import mock

        from netmon.collect import link as first_hop

        reply = ("PING 198.51.100.7 (198.51.100.7): 56 data bytes\n"
                 "64 bytes from 198.51.100.7: icmp_seq=0 ttl=52 time=25.00 ms\n"
                 "\n--- 198.51.100.7 ping statistics ---\n"
                 "1 packets transmitted, 1 packets received, 0.0% packet loss\n")

        def fake_run(argv, timeout=None, stdin=""):
            from netmon.util import CmdResult
            return CmdResult(list(argv), 0, reply, "")

        with mock.patch.object(first_hop, "run", fake_run):
            block = first_hop.collect({"gateway": "192.0.2.1",
                                       "allow_tunnel_probe": True,
                                       "tunnel_endpoint": ENDPOINT})
        prev = obs(vpn=vpn_state("connected"), security="WPA2_PSK")
        cur = obs(ts="2026-01-01T00:00:15Z",
                  vpn=vpn_state("disconnected", reason=ENDPOINT_REASON),
                  security="WPA2_PSK")
        cur.data["link"] = block
        f = by_kind(judge(prev, cur), "VPN_DISCONNECTED")
        self.assertEqual(f.evidence["tunnel_endpoint"], {"id": "ipv4", "v": ENDPOINT})
        self.assertTrue(f.evidence["tunnel_endpoint_reachable"])
        self.assertEqual(f.evidence["tunnel_endpoint_rtt_ms"], 25.0)
        self.assertNotIn(ENDPOINT, f.summary)


class TestDropWhileTheLinkIsAbsent(unittest.TestCase):
    """주 인터페이스가 없는 주기의 끊김 (AC-16).

    engine 이 그 주기를 조기 반환해서 끊김이 이벤트에 남지 않았다. 되살리는
    것은 **끊겼다는 사실 하나**이고, 문장은 링크가 없었다는 사실을 함께
    적어 링크가 살아 있는 끊김과 섞이지 않게 한다.
    """

    def _absent(self, ts="2026-01-01T00:00:05Z", state="disconnected",
                reason="No Network"):
        """링크가 없는 주기의 관측. VPN 상태는 그와 무관하게 수집된다."""
        o = obs(ts=ts, gateway=None, gw_mac=None, icmp_ok=None,
                vpn=vpn_state(state, reason=reason))
        o.data["iface"]["primary"] = None
        o.data["iface"]["primary_kind"] = "unknown"
        o.data["wifi"] = {"applicable": False, "reason": "링크 없음"}
        return o

    def _run(self, cur=None, state=None, prev="connected"):
        return vpn_rules.without_link(
            vpn_state(prev) if prev else prev,
            cur if cur is not None else self._absent(),
            {} if state is None else state)

    def test_the_drop_is_reported_with_the_same_kind_and_grade(self):
        found, _ = self._run()
        self.assertEqual([f.kind for f in found], ["VPN_DISCONNECTED"])
        f = found[0]
        self.assertEqual((f.axis, f.severity, f.confidence),
                         ("quality", "medium", "confirmed"))
        self.assertIsNone(f.attribution)

    def test_the_summary_says_the_link_was_absent(self):
        f = self._run()[0][0]
        self.assertEqual(
            f.summary,
            " ".join([msg.VPN_DISCONNECTED_NO_LINK % ("warp", "disconnected"),
                      msg.VPN_PROVIDER_REASON % "No Network"]))
        # 평소 주기의 문장과 섞이지 않는다.
        self.assertNotIn(msg.VPN_DISCONNECTED % ("warp", ""), f.summary)

    def test_connecting_is_not_called_a_drop_here_either(self):
        """AC-9 는 이 경로에도 그대로 적용된다.

        `was == connected` 이고 `now` 가 connected·unknown·빈값이 아니면
        여기 들어오므로, **`connecting` 인 주기가 그대로 들어온다.** 링크가
        빠지는 끊김에서는 첫 비연결 관측이 `connecting` 일 수 있고, 보관
        표본을 재생해 보면 실제로 그런 주기가 있다(2026-09-17 05시 42분 14초
        UTC — 직전 주기 connected, 주 인터페이스 없음, 공급자 상태 connecting).
        판정 종류·축·등급은 평소와 같고 바뀌는 것은 문장뿐이다.
        """
        f = self._run(self._absent(state="connecting"))[0][0]
        self.assertEqual((f.kind, f.axis, f.severity, f.confidence),
                         ("VPN_DISCONNECTED", "quality", "medium", "confirmed"))
        self.assertEqual(f.evidence["provider_state"], "connecting")
        self.assertEqual(
            f.summary,
            " ".join([msg.VPN_RENEGOTIATING_NO_LINK % "warp",
                      msg.VPN_PROVIDER_REASON % "No Network"]))
        # "연결 끊김" 으로 적지 않는다 — 공급자 자신은 다시 맺는 중이라고 한다.
        self.assertNotIn(msg.VPN_DISCONNECTED_NO_LINK % ("warp", "connecting"),
                         f.summary)
        for code in ("ko", "en"):
            with self.subTest(lang=code):
                head = messages.get("VPN_DISCONNECTED", code).split("%s", 1)[1]
                self.assertNotIn(head.split(".")[0].strip(),
                                 messages.get("VPN_RENEGOTIATING_NO_LINK", code))

    def test_it_does_not_pick_a_likely_cause(self):
        """재지 못한 관측으로 원인을 고르지 않는다.

        실측에서 이 자리에 "가장 유력한 설명: 네트워크 이동" 이 붙었다
        (2026-09-21 05:49:17). 링크가 없는 주기에는 첫 홉도 리졸버도
        재지 못하므로 고를 근거가 없다.
        """
        f = self._run()[0][0]
        for word in ("가장 유력한 설명", "네트워크 이동", "첫 홉"):
            self.assertNotIn(word, f.summary)

    def test_only_the_fixed_reason_is_quoted(self):
        """사유 문자열에는 주소·포트가 섞여 있고 요약문은 가려지지 않는다."""
        cur = self._absent(reason=ENDPOINT_REASON)
        f = self._run(cur)[0][0]
        self.assertNotIn(ENDPOINT, f.summary)
        self.assertEqual(f.summary,
                         msg.VPN_DISCONNECTED_NO_LINK % ("warp", "disconnected"))
        # 원문은 근거에 그대로 남는다 (AC-5 와 같은 기준).
        self.assertEqual(f.evidence["provider_reason"], ENDPOINT_REASON)

    def test_nothing_that_was_not_measured_becomes_evidence(self):
        """비어 있는 관측을 근거로 쓰지 않는다.

        이 주기에 남는 것은 공급자가 보고한 값과 "링크가 없었다" 뿐이다.
        첫 홉·엔드포인트·귀속은 재지도 계산하지도 않았다.
        """
        f = self._run()[0][0]
        self.assertEqual(set(f.evidence), {"provider", "provider_state",
                                           "provider_reason", "prev_state",
                                           "link_absent", "down_since"})
        self.assertIs(f.evidence["link_absent"], True)
        self.assertEqual(f.evidence["prev_state"], "connected")

    def test_protection_loss_is_not_judged_here(self):
        """보호 상실은 이 네트워크의 암호화 방식을 읽어야 한다 — 그 값이 없다."""
        found, _ = self._run()
        self.assertNotIn("VPN_PROTECTION_LOST", [f.kind for f in found])

    def test_a_state_that_could_not_be_read_is_not_a_drop(self):
        for state in ("unknown", None, ""):
            with self.subTest(state=state):
                cur = self._absent(state=state or "unknown")
                cur.data["vpn"]["warp"]["state"] = state
                self.assertEqual(self._run(cur)[0], [])

    def test_a_provider_still_up_is_not_a_drop(self):
        cur = self._absent(state="connected", reason=None)
        self.assertEqual(self._run(cur)[0], [])

    def test_nothing_is_claimed_without_a_previous_cycle(self):
        """"모른다" 와 "방금 끊겼다" 는 다르다. 프로세스의 첫 주기가 그렇다."""
        found, state = vpn_rules.without_link(None, self._absent(), {})
        self.assertEqual(found, [])
        self.assertEqual(state, {})

    def test_an_outage_already_under_way_is_not_reported_again(self):
        """직전 주기에도 끊겨 있었으면 이번 주기에 시작된 끊김이 아니다."""
        found, state = vpn_rules.without_link(vpn_state("disconnected"),
                                              self._absent(), {})
        self.assertEqual(found, [])
        self.assertEqual(state, {})

    def test_the_start_time_comes_from_the_state_when_it_is_there(self):
        found, _ = self._run(state={"vpn_down_since":
                                    {"warp": "2026-01-01T00:00:05Z"}})
        self.assertEqual(found[0].evidence["down_since"], "2026-01-01T00:00:05Z")

    def test_a_broken_start_time_falls_back_to_this_cycle(self):
        for downs in ({"warp": None}, {"warp": 12345}, {"warp": "x"}, "x", None):
            with self.subTest(downs=downs):
                found, _ = self._run(state={"vpn_down_since": downs})
                self.assertEqual(found[0].evidence["down_since"],
                                 "2026-01-01T00:00:05Z")

    def test_user_action_keeps_the_grading_it_has_elsewhere(self):
        cur = self._absent(reason="Manual_Disconnection")
        f = self._run(cur)[0][0]
        self.assertEqual((f.severity, f.attribution), ("info", "user_action"))

    def test_it_marks_the_outage_as_reported(self):
        found, state = self._run()
        since = found[0].evidence["down_since"]
        self.assertEqual(state["vpn_down_reported"], {"warp": since})
        self.assertTrue(vpn_rules.already_reported(
            dict(state, vpn_down_since={"warp": since}), "warp"))

    def test_a_broken_state_does_not_raise(self):
        """상태 파일은 손으로 고칠 수 있고 재시작을 건너뛰어 남는다."""
        for state, reported in (("x", 0), (None, 0), (12, 0),
                                ({"vpn_down_reported": "x"}, 1),
                                ({"vpn_down_reported": {"warp": 5}}, 1)):
            with self.subTest(state=state):
                found, back = vpn_rules.without_link(
                    vpn_state("connected"), self._absent(), state)
                self.assertEqual(len(found), reported)
                if not reported:
                    # 읽을 수 없는 상태를 고쳐 쓰지 않는다. 그대로 돌려준다.
                    self.assertIs(back, state)

    def test_the_mark_only_covers_the_outage_it_was_made_for(self):
        """상태 파일에 남은 옛 표시가 다음 끊김까지 덮으면 안 된다."""
        state = {"vpn_down_reported": {"warp": "2026-01-01T00:00:05Z"},
                 "vpn_down_since": {"warp": "2026-01-01T09:00:00Z"}}
        self.assertFalse(vpn_rules.already_reported(state, "warp"))
        for broken in ({"warp": None}, {"warp": "x"}, "x", None, {}):
            with self.subTest(reported=broken):
                self.assertFalse(vpn_rules.already_reported(
                    {"vpn_down_reported": broken,
                     "vpn_down_since": {"warp": "2026-01-01T00:00:05Z"}},
                    "warp"))


class TestTheRecoveryReadsTheStateTheEngineActuallyWrote(unittest.TestCase):
    """상태 키가 한쪽에서만 바뀌어도 잡히는가 (DEV-13 (a)).

    위 `TestTheOutageCarriesItsEndpointTally` 를 포함해 커밋된 시험은 모두
    상태를 **손으로** 주입한다. 그래서 쓰는 쪽(netmon/engine.py)과 읽는 쪽
    (netmon/detect/vpn.py)의 이름이 갈라져도 전부 통과한 채 복구 증거의
    `tunnel_endpoint_shots`·`tunnel_endpoint_cap_reached` 두 필드만 조용히
    사라진다. 여기서는 **엔진이 만든 상태 dict 를 그대로** 판정에 먹이고,
    키 이름을 이 파일 어디에도 적지 않는다.
    """

    def _engine(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        cfg = configmod.load(os.path.join(d, "config.json"))
        cfg.grant("external_probes", note="테스트")
        cfg.set_feature("vpn.tunnel_probe", True)
        eng = Engine.__new__(Engine)
        eng.cfg = cfg
        eng.state = {}
        eng._last_vpn = vpn_state("disconnected", reason=ENDPOINT_REASON)
        return eng

    def _reconnect(self, engine_state):
        prev = obs(ts="2026-01-01T00:07:25Z", vpn=vpn_state("disconnected"))
        cur = obs(ts="2026-01-01T00:07:30Z", vpn=vpn_state("connected"))
        state = dict(engine_state)
        state.update({"icmp_gw": True,
                      "vpn_down_since": {"warp": "2026-01-01T00:00:00Z"}})
        return by_kind(judge(prev, cur, state=state), "VPN_RECONNECTED")

    def test_the_shots_the_engine_counted_reach_the_recovery_evidence(self):
        eng = self._engine()
        for _ in range(2):
            eng._claim_tunnel_probe()
        f = self._reconnect(eng.state)
        self.assertEqual(f.evidence["tunnel_endpoint_shots"], 2)
        self.assertFalse(f.evidence["tunnel_endpoint_cap_reached"])

    def test_a_capped_outage_written_by_the_engine_reads_back_as_capped(self):
        eng = self._engine()
        for _ in range(vpnmod.TUNNEL_PROBE_CAP + 1):
            eng._claim_tunnel_probe()
        f = self._reconnect(eng.state)
        self.assertEqual(f.evidence["tunnel_endpoint_shots"],
                         vpnmod.TUNNEL_PROBE_CAP)
        self.assertTrue(f.evidence["tunnel_endpoint_cap_reached"])


class TestACycleWeCouldNotMeasureStaysUnmeasuredInTheEvidence(unittest.TestCase):
    """수집기의 실패 갈래가 판정까지 그대로 이어지는가 (DEV-13 (d)(e)(f)).

    모양을 손으로 적지 않고 **수집기를 실제로 돌려** 만든 관측으로 본다.
    손으로 적으면 생산자가 바뀔 때 같이 틀어진다.
    """

    def _judge(self, block):
        prev = obs(vpn=vpn_state("connected"), security="WPA2_PSK")
        cur = obs(ts="2026-01-01T00:00:15Z",
                  vpn=vpn_state("disconnected"), security="WPA2_PSK")
        cur.data["link"] = block
        cur.data["link"]["gateway_reachable"] = \
            block.get("results", {}).get("gateway", {}).get("reachable")
        return by_kind(judge(prev, cur), "VPN_DISCONNECTED")

    def _timed_out_cycle(self):
        """결과를 기다리다 만 주기 — future 가 실제로 시간을 넘긴다."""
        def slow(argv, timeout=None, stdin=""):
            import time
            time.sleep(0.2)
            from netmon.util import CmdResult
            return CmdResult(list(argv), 0, "", "")

        with mock.patch.object(first_hop, "run", slow), \
                mock.patch.object(first_hop, "RESULT_WAIT_SECONDS", 0.01):
            return first_hop.collect({"gateway": "192.0.2.1"})

    def test_a_future_that_timed_out_still_reaches_the_guards(self):
        """빈 오류 문구면 가드 두 곳이 모두 꺼진다 (DEV-13 (d))."""
        f = self._judge(self._timed_out_cycle())
        self.assertEqual(f.evidence["first_hop_errors"], [PROBE_TIMED_OUT])
        self.assertTrue(vpn_rules.first_hop_not_run(
            f.evidence["first_hop_method"], f.evidence))
        self.assertIn(msg.WHY_FIRST_HOP_TIMED_OUT, f.summary)
        self.assertNotIn(msg.WHY_LINK % msg.METHOD_ICMP, f.summary)
        self.assertNotIn(msg.FIRST_HOP_EVIDENCE_ONE_COMMAND, f.summary)

    def test_an_unmeasured_cycle_carries_no_loss_rate(self):
        """재지 못한 주기에 `손실 100%` 가 측정값처럼 남지 않는다 (DEV-13 (f)).

        `ping()` 은 실행에 실패해도 `parse_ping("")` 의 결과를 그대로 두므로
        관측에는 `replies 0`·`loss_pct 100.0` 이 오류와 함께 실린다. 증거만
        기계로 읽는 쪽에는 그것이 잰 값으로 보인다.
        """
        def missing(argv, timeout=None, stdin=""):
            from netmon import util
            return util.run(["netmon-no-such-command-for-tests"])

        with mock.patch.object(first_hop, "run", missing):
            block = first_hop.collect({"gateway": "192.0.2.1"})
        # 관측에는 여전히 그 값들이 있다 — 거르는 것은 증거 쪽이다.
        self.assertEqual(block["results"]["gateway"]["loss_pct"], 100.0)
        f = self._judge(block)
        self.assertEqual(f.evidence["first_hop_errors"], [PROBE_NOT_RUN])
        self.assertNotIn("first_hop_loss_pct", f.evidence)
        self.assertNotIn("first_hop_received", f.evidence)
        # 판정은 종전 그대로 "재지 못함" 이다.
        self.assertTrue(vpn_rules.first_hop_not_run(
            f.evidence["first_hop_method"], f.evidence))

    def test_a_measured_single_cycle_still_carries_both(self):
        """가드가 넘치지 않는다 — 실제로 잰 평소 주기는 종전대로다."""
        f = by_kind(judge(obs(vpn=vpn_state("connected"), security="WPA2_PSK"),
                          one_command(obs(ts="2026-01-01T00:00:15Z",
                                          vpn=vpn_state("disconnected"),
                                          security="WPA2_PSK"),
                                      sent=3, received=1)),
                    "VPN_DISCONNECTED")
        self.assertEqual(f.evidence["first_hop_received"], 1)
        self.assertEqual(f.evidence["first_hop_loss_pct"], 66.7)

    def test_no_path_from_a_raised_oserror_reaches_the_evidence(self):
        """경로가 든 예외 메시지가 증거로 들어가지 않는다 (DEV-13 (e)).

        `util.run` 은 이 OSError 를 잡지 않는다. 메시지가 `first_hop_errors`
        로 실리면 감싸지 않은 문자열이라 `capture --redact` 에도 살아남는다.
        """
        # 합성 경로다 (tools/leak-check.sh 의 PATH 규칙).
        path = "/opt/netmon-not-a-real-path/bin/ping"

        def exploding(argv, timeout=None, stdin=""):
            raise OSError(8, "Exec format error", path)

        with mock.patch.object(first_hop, "run", exploding):
            block = first_hop.collect({"gateway": "192.0.2.1"})
        f = self._judge(block)
        self.assertEqual(f.evidence["first_hop_errors"], ["OSError"])
        self.assertNotIn(path, repr(f.evidence))
        self.assertNotIn(path, f.summary)
        # 가렸다고 넘어가지 않는다 — 감싸지 않은 문자열은 그대로 나간다.
        redacted = redactmod.redact(dict(f.evidence), b"salt-for-tests")
        self.assertNotIn(path, repr(redacted))
        self.assertIn(path, repr(redactmod.redact({"error": str(
            OSError(8, "Exec format error", path))}, b"salt-for-tests")))


class TestTheLinkLessSummaryDoesNotUndersellTheCycle(unittest.TestCase):
    """잰 것을 재지 않은 것처럼 적지 않는다 (DEV-13 (h)).

    DEV-11 이 넣은 문구는 "다른 관측도 비어 있어" / "the rest of the cycle was
    not measured" 였다. 링크가 없는 주기에도 수집 단계는 **전부 돌고**, 엔진은
    그 주기에 Wi-Fi 를 **일부러 더 읽는다**(netmon/engine.py 의
    `wifi_fallback_dev` — 주 인터페이스가 없을 때가 무선 상태를 가장 알고 싶은
    순간이기 때문이다. `link_active`·암호화 방식이 거기서 나온다). 정확히는
    "이 판정이 그 관측을 읽지 않는다" 다.
    """

    def _absent(self, state="disconnected"):
        """링크가 없는 주기. **Wi-Fi 는 엔진이 더 읽어 둔 모양으로 채운다.**"""
        o = obs(ts="2026-01-01T00:00:05Z", gateway=None, gw_mac=None,
                icmp_ok=None, vpn=vpn_state(state, reason="No Network"))
        o.data["iface"]["primary"] = None
        o.data["iface"]["primary_kind"] = "unknown"
        o.data["wifi"] = {"applicable": True, "is_primary": False,
                          "security": "WPA2_PSK", "link_active": True,
                          "location": "denied", "ssid": None, "bssid": None}
        return o

    def _finding(self, state="disconnected"):
        found, _ = vpn_rules.without_link(vpn_state("connected"),
                                          self._absent(state), {})
        return found[0]

    def test_the_cycle_really_does_carry_other_observations(self):
        """전제를 관측으로 고정한다. 이것이 참이라 옛 문장이 틀렸다."""
        cur = self._absent()
        self.assertTrue(cur.data["wifi"]["applicable"])
        self.assertEqual(cur.data["wifi"]["security"], "WPA2_PSK")
        self.assertIs(cur.data["wifi"]["link_active"], True)

    def test_neither_summary_says_the_rest_of_the_cycle_was_empty(self):
        for state in ("disconnected", "connecting"):
            with self.subTest(state=state):
                summary = self._finding(state).summary
                for word in ("비어 있", "재지 못", "측정하지"):
                    self.assertNotIn(word, summary)

    def test_both_catalogues_say_what_the_judgement_reads_instead(self):
        for code, gone, kept in (
                ("ko", "비어 있", "공급자가 보고한 상태"),
                ("en", "was not measured", "nothing but the state the provider")):
            for key in ("VPN_DISCONNECTED_NO_LINK", "VPN_RENEGOTIATING_NO_LINK"):
                with self.subTest(lang=code, key=key):
                    text = messages.get(key, code)
                    self.assertNotIn(gone, text)
                    self.assertIn(kept, text)

    def test_reading_nothing_else_is_still_what_the_judgement_does(self):
        """문구만 고치고 동작을 바꾸지 않았다 — 근거는 여전히 공급자 값뿐이다."""
        f = self._finding()
        self.assertEqual(set(f.evidence), {"provider", "provider_state",
                                           "provider_reason", "prev_state",
                                           "link_absent", "down_since"})
        # Wi-Fi 를 읽었다면 보호 상실 판정이 났을 것이다. 나지 않는다.
        found, _ = vpn_rules.without_link(vpn_state("connected"),
                                          self._absent(), {})
        self.assertEqual([x.kind for x in found], ["VPN_DISCONNECTED"])


if __name__ == "__main__":
    unittest.main()
