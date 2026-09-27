"""VPN 판정 — 상태 전환과 끊김.

원본 스크립트는 끊김 원인을 하나만 골랐다. 여기서는 한 번의 끊김이 품질과
보안 두 축에 따로 기록되고, "왜"는 분류가 아니라 근거로 붙는다.
"""
from __future__ import annotations

import contextlib
import itertools
import json
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

    def test_manual_disconnect_still_raises_protection_loss(self):
        """직접 끊었어도 보호 상실 판정은 남는다. 억제 사유가 user_action 으로 붙고
        등급은 low 로 내려간다."""
        prev = obs(vpn=vpn_state("connected"), security="WPA2_PSK")
        cur = obs(vpn=vpn_state("disconnected", reason="Manual_Disconnection"),
                  security="WPA2_PSK")
        f = by_kind(judge(prev, cur), "VPN_PROTECTION_LOST")
        self.assertIsNotNone(f)
        self.assertEqual(f.attribution, "user_action")
        self.assertEqual(f.severity, "low")

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
        self.assertEqual(f.summary, "%s %s" % (msg.VPN_PROTECTION_LOST_HEAD % "warp",
                                               msg.VPN_PROTECTION_LOST))

    def test_enterprise_network_does_not_claim_exposure(self):
        prev = obs(vpn=vpn_state("connected"), security="WPA2 Enterprise")
        cur = obs(vpn=vpn_state("disconnected"), security="WPA2 Enterprise")
        self.assertIsNone(by_kind(judge(prev, cur), "VPN_PROTECTION_LOST"))

    def test_unknown_security_says_so_instead_of_guessing(self):
        prev = obs(vpn=vpn_state("connected"), iface_kind="ethernet")
        cur = obs(vpn=vpn_state("disconnected"), iface_kind="ethernet")
        f = by_kind(judge(prev, cur), "VPN_PROTECTION_LOST")
        self.assertIsNotNone(f)
        self.assertEqual(f.summary, "%s %s" % (msg.VPN_PROTECTION_LOST_HEAD % "warp",
                                               msg.VPN_PROTECTION_LOST_UNKNOWN))
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
    다시 맺는 중인 것과 끊어진 것은 다른 사실이다. **판정 종류·등급·조사
    개시는 그대로 둔다.** 보호 상실 판정도 두 상태에서 똑같이 나고, 그 요약문
    머리말도 같은 기준으로 재협상을 구분한다(사용자 결정 2026-09-23 — 한 주기의
    같은 관측값을 품질 축은 "재협상 중", 보안 축은 "끊김" 이라고 적고 있었다).
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

    def test_protection_loss_keeps_its_kind_severity_and_suppression(self):
        a = by_kind(self._drop("connecting"), "VPN_PROTECTION_LOST")
        b = by_kind(self._drop("disconnected"), "VPN_PROTECTION_LOST")
        self.assertIsNotNone(a)
        self.assertEqual(a.severity, "medium")
        self.assertEqual((a.axis, a.severity, a.attribution, set(a.evidence)),
                         (b.axis, b.severity, b.attribution, set(b.evidence)))

    def test_protection_loss_head_says_renegotiation(self):
        a = by_kind(self._drop("connecting"), "VPN_PROTECTION_LOST")
        self.assertEqual(a.summary, "%s %s" % (
            msg.VPN_PROTECTION_LOST_HEAD_RENEGOTIATING % "warp", msg.VPN_PROTECTION_LOST))
        self.assertNotIn("끊김", messages.get("VPN_PROTECTION_LOST_HEAD_RENEGOTIATING", "ko"))
        self.assertNotIn("dropped", messages.get("VPN_PROTECTION_LOST_HEAD_RENEGOTIATING", "en"))

    def test_both_axes_name_the_reported_state_in_the_same_cycle(self):
        """두 축이 같은 주기의 같은 값을 같게 적는다. 두 카탈로그 모두 공급자
        상태 이름(connecting)을 그대로 인용하므로 활성 언어와 무관하게 본다."""
        found = self._drop("connecting")
        for kind in ("VPN_DISCONNECTED", "VPN_PROTECTION_LOST"):
            self.assertIn("connecting", by_kind(found, kind).summary, kind)
        for kind in ("VPN_DISCONNECTED", "VPN_PROTECTION_LOST"):
            self.assertNotIn("connecting", by_kind(self._drop("disconnected"), kind).summary,
                             kind)


class TestProviderReasonInTheSummary(unittest.TestCase):
    """사유는 고정 목록과 **정확히 일치할 때만** 요약문에 인용한다.

    사유 문자열에는 터널 엔드포인트의 공인 IP·포트가 들어 있고, 요약문은
    가리지 않은 채로 보고서에 나간다(redact 는 요약문을 바꾸지 않는다 —
    netmon/redact.py 의 자유 문자열 필드에 요약문은 없다).
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




class TestWarpDaemonLogReading(unittest.TestCase):
    """WARP 데몬 로그를 이어 읽는다 (DEV-2 — QA-1, QA-2, QA-5, ADV-5, ADV-6, ADV-8).

    읽는 쪽의 약속: 직전 주기 뒤에 붙은 **완결된 줄**만 돌려준다. 개행 없는 마지막 줄은
    데몬이 아직 쓰는 중일 수 있어 다음 주기로 미룬다. 회전(이름 바꾸기)과 두 번 회전,
    잘림, 한 주기 상한을 넘는 경우에도 줄이 겹치거나 빠지지 않는다 — 빠질 수밖에 없을
    때(상한 초과, 회전본을 못 찾음, 회전본의 개행 없는 꼬리를 버림)는 `reset` 으로 알린다.
    """

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.path = os.path.join(self.d, "cfwarp_service_log.txt")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def write(self, text, path=None, mode="a"):
        with open(path or self.path, mode, encoding="utf-8") as fh:
            fh.write(text)

    def rotate(self):
        """데몬처럼 이름을 밀어낸다: .2→.3, .1→.2, 현재→.1, 새 현재."""
        for i in (2, 1):
            src = "%s.%d" % (self.path, i)
            if os.path.exists(src):
                os.replace(src, "%s.%d" % (self.path, i + 1))
        os.replace(self.path, self.path + ".1")
        self.write("", mode="w")

    def read(self, pos, cap=vpnmod.WARP_DAEMON_READ_CAP):
        return vpnmod.read_warp_daemon(pos, path=self.path, cap=cap)

    def test_first_start_begins_at_the_end(self):
        self.write("old 1\nold 2\n")
        lines, pos, info = self.read(None)
        self.assertEqual(lines, [])
        self.assertEqual(info["read"], "ok")
        self.write("new 1\n")
        lines, pos, info = self.read(pos)
        self.assertEqual(lines, ["new 1"])

    def test_first_start_waits_for_a_half_written_last_line(self):
        self.write("old 1\nhalf")
        lines, pos, _ = self.read(None)
        self.write(" done\n")
        lines, _, _ = self.read(pos)
        self.assertEqual(lines, ["half done"])

    def test_only_new_complete_lines(self):
        self.write("a\n")
        _, pos, _ = self.read(None)
        self.write("b\nc\npartial")
        lines, pos, info = self.read(pos)
        self.assertEqual(lines, ["b", "c"])
        self.assertFalse(info["reset"])
        self.write(" line\n")
        lines, pos, _ = self.read(pos)
        self.assertEqual(lines, ["partial line"])

    def test_a_restart_resumes_from_the_saved_position(self):
        self.write("a\n")
        _, pos, _ = self.read(None)
        self.write("b\n")
        saved = json.loads(json.dumps(pos))          # state.json 을 거친 것처럼
        lines, _, info = self.read(saved)
        self.assertEqual(lines, ["b"])
        self.assertFalse(info["reset"])

    def test_single_rotation_keeps_the_tail_of_the_old_file(self):
        self.write("a\n")
        _, pos, _ = self.read(None)
        self.write("b\n")
        self.rotate()
        self.write("c\n")
        lines, _, info = self.read(pos)
        self.assertEqual(lines, ["b", "c"])
        self.assertFalse(info["reset"])

    def test_a_rotated_file_that_ends_mid_line_does_not_make_a_line(self):
        """회전본이 개행 없이 끝나면 그 꼬리는 완결 줄이 아니다 — 버리고 연속성이 끊긴 것으로 알린다(TODO K-4, DEV-8).
        완결 줄로 치면 쓰이다 만 `…ResponseStatus: Conn` 이 가짜 상태가 되어 Connected→비연결→Connected 모양이 된다."""
        self.write("a\n")
        _, pos, _ = self.read(None)
        self.write(daemon_status("Connected") + "\n" + daemon_status("Conn"))      # 쓰이다 만 줄에서 회전
        self.rotate()
        self.write(daemon_status("Connected") + "\n")
        lines, pos, info = self.read(pos)
        self.assertEqual(lines, [daemon_status("Connected"), daemon_status("Connected")])
        self.assertTrue(info["reset"])
        kept, _, _, _ = vpnmod.parse_warp_daemon(lines, None)
        self.assertEqual([k["text"] for k in kept], ["Connected"])
        self.write("b\n")
        lines, _, info = self.read(pos)
        self.assertEqual((lines, info["reset"]), (["b"], False))

    def test_an_older_rotated_file_that_ends_mid_line_or_has_no_newline(self):
        self.write("a\n")
        _, pos, _ = self.read(None)
        self.write("b\nhal")                  # 두 번 회전하는 동안 .2 가 될 파일
        self.rotate()
        self.write("no newline at all")       # .1 이 될 파일 — 줄 끝이 하나도 없다
        self.rotate()
        self.write("c\n")
        lines, _, info = self.read(pos)
        self.assertEqual(lines, ["b", "c"])
        self.assertTrue(info["reset"])

    def test_a_skip_that_starts_inside_a_rotated_file_without_a_newline_loses_no_complete_line(self):
        """상한 초과로 건너뛴 자리가 줄 끝 없는 회전본 안이면, 그 조각이 "건너뛴 뒤의 첫 줄" 이다 — 다음 파일의 완결 줄을 버리지 않는다."""
        self.write("a\n")
        _, pos, _ = self.read(None)
        self.write("x" * 100)
        self.rotate()
        self.write("c\nd\n")
        lines, _, info = self.read(pos, cap=50)
        self.assertEqual(lines, ["c", "d"])
        self.assertTrue(info["reset"])
        self.assertGreater(info["skipped_bytes"], 0)

    def test_a_skip_inside_a_rotated_file_that_ends_mid_line_still_drops_the_tail(self):
        """건너뛴 자리에서 시작한 회전본 조각이라도 줄 끝이 있으면, 마지막 개행 뒤 꼬리는 버린다(예외는 줄 끝이 하나도 없을 때만)."""
        self.write("a\n")
        _, pos, _ = self.read(None)
        self.write("x" * 80 + "\nmid\nCONN")
        self.rotate()
        self.write("c\nd\n")
        lines, _, info = self.read(pos, cap=30)
        self.assertEqual(lines, ["mid", "c", "d"])
        self.assertTrue(info["reset"])

    def test_a_later_rotated_file_without_a_newline_after_a_skip_is_still_a_tail(self):
        """예외는 건너뛴 자리에서 시작한 **첫** 조각에만 — 뒤따르는 줄 끝 없는 회전본은 꼬리로 버린다."""
        self.write("a\n")
        _, pos, _ = self.read(None)
        self.write("x" * 80 + "\nok\n")
        self.rotate()
        self.write("PARTIAL")
        self.rotate()
        self.write("c\n")
        lines, _, info = self.read(pos, cap=30)
        self.assertEqual(lines, ["ok", "c"])
        self.assertTrue(info["reset"])

    def test_a_truncated_then_rotated_file_without_a_newline_is_a_tail_not_a_line(self):
        """DEV-14 (DEV-8 2회차 [낮음] M12·M13): 저장 위치가 회전본 크기보다 커 잘림으로 처리되고(건너뜀 없음) 그 회전본에 개행이
        하나도 없으면, 그 조각은 건너뛴 자리의 조각이 아니라 쓰이다 만 꼬리다 — 버린다."""
        self.write("a\n" * 200)                               # 저장 위치 400 > 아래 쓰다 만 줄의 길이
        _, pos, _ = self.read(None)
        self.write(daemon_status("Conn"), mode="w")          # 같은 파일을 잘라 쓰다 만 줄 하나
        self.assertLess(len(daemon_status("Conn")), pos["offset"])
        self.rotate()
        self.write(daemon_status("Connected") + "\n")
        lines, _, info = self.read(pos)
        self.assertEqual(lines, [daemon_status("Connected")])
        self.assertTrue(info["reset"])
        self.assertEqual(info["skipped_bytes"], 0)

    def test_double_rotation(self):
        self.write("a\n")
        _, pos, _ = self.read(None)
        self.write("b\n")
        self.rotate()
        self.write("c\n")
        self.rotate()
        self.write("d\n")
        lines, _, info = self.read(pos)
        self.assertEqual(lines, ["b", "c", "d"])
        self.assertFalse(info["reset"])

    def test_a_rotation_in_the_middle_of_a_read_loses_and_repeats_nothing(self):
        """ADV-5: 크기를 잰 뒤 파일을 여는 사이에 데몬이 회전해도 줄이 겹치거나 빠지지 않는다.

        새 파일이 저장 위치보다 이미 길면, 옛 파일의 위치로 새 파일을 읽어 엉뚱한 줄을
        돌려주고 그 위치를 옛 파일의 것으로 저장하게 된다. 그 주기는 읽지 않은 것으로 두고
        다음 주기에 다시 읽어야 한다.
        """
        self.write("a\n")
        _, pos, _ = self.read(None)
        self.write("b\nc\n")
        real = vpnmod._read_range
        calls = []

        def rotate_first(path, start, end):
            if not calls:
                self.rotate()
                self.write("x1\nx2\nx3\n")
            calls.append(path)
            return real(path, start, end)

        with mock.patch.object(vpnmod, "_read_range", side_effect=rotate_first):
            first, pos, info = self.read(pos)
        self.assertFalse(info["reset"])
        second, _, info = self.read(pos)
        self.assertEqual(first + second, ["b", "c", "x1", "x2", "x3"])
        self.assertFalse(info["reset"])

    def test_a_rotation_right_after_the_size_is_taken(self):
        """크기를 잰 직후, 읽기 전 식별을 적기 전에 회전이 껴도 같다."""
        self.write("a\n")
        _, pos, _ = self.read(None)
        self.write("b\nc\n")
        real = vpnmod._rotation_ids
        calls = []

        def rotate_first(path):
            if not calls:
                self.rotate()
                self.write("x1\nx2\nx3\n")
            calls.append(path)
            return real(path)

        with mock.patch.object(vpnmod, "_rotation_ids", side_effect=rotate_first):
            first, pos, _ = self.read(pos)
        second, _, info = self.read(pos)
        self.assertEqual(first + second, ["b", "c", "x1", "x2", "x3"])
        self.assertFalse(info["reset"])

    def test_a_rotation_in_the_middle_of_the_first_read_starts_over(self):
        """처음 켤 때 끝을 찾는 사이 회전이 끼면 위치를 남기지 않고 다음 주기에 다시 끝에서 시작한다."""
        self.write("old 1\nold 2\n")
        real = vpnmod._read_range

        def rotate_then_read(path, start, end):
            self.rotate()
            return real(path, start, end)

        with mock.patch.object(vpnmod, "_read_range", side_effect=rotate_then_read):
            lines, pos, info = self.read(None)
        self.assertEqual((lines, pos, info["reset"]), ([], None, True))

    def test_a_read_with_no_new_bytes_returns_nothing_and_keeps_the_position(self):
        """QA-2: 새 바이트가 없으면 줄도 없고 reset 도 아니며 위치가 그대로다(크기 == 저장 위치는 잘림이 아니다)."""
        self.write("a\nb\n")
        _, pos, _ = self.read(None)
        lines, again, info = self.read(pos)
        self.assertEqual((lines, info["reset"], again["offset"]), ([], False, pos["offset"]))

    def test_a_rotation_right_after_reading_to_the_end_repeats_nothing(self):
        """ADV-5: 끝까지 읽은 뒤(저장 위치 == 옛 파일 크기) 회전하면 새 파일의 줄만 나온다."""
        self.write("a\n")
        _, pos, _ = self.read(None)
        self.write("b\nc\n")
        _, pos, _ = self.read(pos)
        self.rotate()
        self.write("d\n")
        lines, _, info = self.read(pos)
        self.assertEqual((lines, info["reset"]), (["d"], False))

    def test_a_triple_rotation_is_still_followed(self):
        self.write("a\n")
        _, pos, _ = self.read(None)
        self.write("b\n")
        for text in ("c\n", "d\n", "e\n"):
            self.rotate()
            self.write(text)
        lines, _, info = self.read(pos)
        self.assertEqual((lines, info["reset"]), (["b", "c", "d", "e"], False))

    def test_a_stat_that_fails_for_another_reason_is_unreadable_and_keeps_the_position(self):
        """AC-5: 없는 것(missing)과 읽을 수 없는 것(unreadable)을 구분하고, 위치는 버리지 않는다."""
        self.write("a\n")
        _, pos, _ = self.read(None)
        with mock.patch.object(vpnmod.os, "stat", side_effect=PermissionError("secret /opt/netmon-not-a-real-path")):
            lines, again, info = self.read(pos)
        self.assertEqual((lines, info["read"], again), ([], "unreadable", pos))
        self.assertNotIn("secret", json.dumps(info))

    def test_rotated_out_of_reach_resets(self):
        self.write("a\n")
        _, pos, _ = self.read(None)
        for _ in range(4):
            self.rotate()
            self.write("x\n")
        lines, _, info = self.read(pos)
        self.assertTrue(info["reset"])
        self.assertEqual(lines, [])

    def test_truncation_reads_from_the_start_and_resets(self):
        self.write("a much longer first line\n")
        _, pos, _ = self.read(None)
        self.write("short\n", mode="w")              # 같은 파일, 크기가 줄었다
        lines, _, info = self.read(pos)
        self.assertEqual(lines, ["short"])
        self.assertTrue(info["reset"])

    def test_over_the_cap_skips_the_front_and_the_cut_line(self):
        """상한 95바이트는 줄 경계(10바이트)에 맞지 않는다 — 건너뛴 자리의 줄 조각을 버려야 한다."""
        self.write("a\n")
        _, pos, _ = self.read(None)
        self.write("".join("line %04d\n" % i for i in range(100)))
        lines, _, info = self.read(pos, cap=95)
        self.assertTrue(info["reset"])
        self.assertEqual(lines[0], "line 0091")
        self.assertEqual(lines[-1], "line 0099")
        self.assertEqual(len(lines), 9)
        # 건너뛴 905바이트 + 버린 조각 "0090\n" 5바이트
        self.assertEqual(info["skipped_bytes"], 910)

    def test_an_empty_current_file_after_rotation_keeps_its_own_position(self):
        """상한을 넘었는데 현재 파일이 막 회전해 비어 있어도 새 위치는 현재 파일의 것이다."""
        self.write("a\n")
        _, pos, _ = self.read(None)
        self.write("".join("line %04d\n" % i for i in range(100)))
        self.rotate()
        lines, pos, info = self.read(pos, cap=100)
        self.assertEqual(lines[-1], "line 0099")
        self.assertEqual((pos["file"], pos["offset"]), (vpnmod._file_id(os.stat(self.path)), 0))
        self.write("c\n")
        lines, _, info = self.read(pos)
        self.assertEqual((lines, info["reset"]), (["c"], False))

    def test_a_rotated_file_shorter_than_the_saved_offset_is_read_from_its_start(self):
        """ADV-8: 회전본의 크기보다 큰 저장 위치는 잘림과 같게 다룬다(처음부터, reset)."""
        self.write("a\nb\n")
        _, pos, _ = self.read(None)
        pos = dict(pos, offset=pos["offset"] + 999)
        self.rotate()
        self.write("c\n")
        lines, _, info = self.read(pos)
        self.assertEqual(lines, ["a", "b", "c"])
        self.assertTrue(info["reset"])

    def test_a_rotated_last_line_without_a_newline_is_dropped_and_reset(self):
        """(DEV-8 에서 바뀜 — 옛 판은 완결 줄로 쳤다. TODO K-4: 쓰이다 만 줄일 수 있어 버리고 reset.)"""
        self.write("a\n")
        _, pos, _ = self.read(None)
        self.write("b")
        self.rotate()
        self.write("c\n")
        lines, _, info = self.read(pos)
        self.assertEqual(lines, ["c"])
        self.assertTrue(info["reset"])

    def test_a_missing_file_in_the_middle_of_a_rotation_is_not_a_read_failure(self):
        """이름이 밀린 뒤 새 파일이 아직 없는 순간에 열어도 실패로 적지 않고 다음 주기에 이어 읽는다."""
        self.write("a\n")
        _, pos, _ = self.read(None)
        self.write("b\n")
        real = vpnmod._read_range
        calls = []

        def rename_first(path, start, end):
            if not calls:
                os.replace(self.path, self.path + ".1")
            calls.append(path)
            return real(path, start, end)

        with mock.patch.object(vpnmod, "_read_range", side_effect=rename_first):
            lines, pos2, info = self.read(pos)
        self.assertEqual((lines, info["read"], pos2), ([], "ok", pos))
        self.write("c\n", mode="w")
        lines, _, info = self.read(pos2)
        self.assertEqual((lines, info["reset"]), (["b", "c"], False))

    def test_the_comparison_state_is_cleared_only_when_continuity_breaks(self):
        """`last_status` 는 이어 읽을 때만 넘어가고, 연속성이 끊기면 비운다(DEV-3 의 반복 방송 생략 기준)."""
        self.write("a\n")
        _, pos, _ = self.read(None)
        pos = dict(pos, last_status="Connected")
        self.write("b\n")
        _, kept, _ = self.read(pos)
        self.assertEqual(kept["last_status"], "Connected")
        self.write("x\n", mode="w")                       # 잘림
        _, cut, info = self.read(kept)
        self.assertEqual((cut["last_status"], info["reset"]), (None, True))
        self.write("".join("line %04d\n" % i for i in range(50)))
        _, over, info = self.read(dict(cut, last_status="Connected"), cap=50)   # 상한 초과
        self.assertEqual((over["last_status"], info["reset"]), (None, True))
        for _ in range(4):
            self.rotate()
        _, gone, info = self.read(dict(over, last_status="Connected"))           # 회전본 밖
        self.assertEqual((gone["last_status"], info["reset"]), (None, True))

    def test_a_missing_log_keeps_the_saved_position(self):
        self.write("a\n")
        _, pos, _ = self.read(None)
        _, same, info = vpnmod.read_warp_daemon(pos, path=os.path.join(self.d, "gone"))
        self.assertEqual((same, info["read"]), (pos, "missing"))

    def test_missing_and_unreadable_leave_no_message(self):
        lines, pos, info = vpnmod.read_warp_daemon(None, path=os.path.join(self.d, "nope"))
        self.assertEqual((lines, info["read"]), ([], "missing"))
        self.write("a\n")
        with mock.patch("builtins.open", side_effect=PermissionError("secret /opt/netmon-not-a-real-path/log")):
            lines, pos2, info = self.read({"file": "1:1", "offset": 0, "last_status": None})
        self.assertEqual((lines, info["read"]), ([], "unreadable"))
        self.assertNotIn("secret", json.dumps(info))

    def test_broken_saved_positions_are_treated_as_missing(self):
        """ADV-6·ADV-8: 깨졌거나 다른 프로세스가 덮어쓴 위치에서 예외가 나지 않는다."""
        self.write("a\nb\n")
        for bad in ("x", 3, [], {"file": 1, "offset": 0}, {"file": "1:2", "offset": -5},
                    {"file": "1:2", "offset": "10"}, {"file": "9:9", "offset": 10 ** 12},
                    {"offset": 0}, {"file": "1:2", "offset": 0, "last_status": 7}):
            lines, pos, info = self.read(bad)
            self.assertEqual(lines, [], bad)
            self.assertTrue(info["reset"], bad)
            self.assertIsInstance(pos["offset"], int)

    def test_broken_values_next_to_the_real_file_id_are_treated_as_missing(self):
        """ADV-6: 식별은 맞는데 값이 깨졌으면 검증에서 걸러 처음 켬과 같게 다룬다(예외도, 영구 실패도 없다)."""
        self.write("a\nb\n")
        _, good, _ = self.read(None)
        fid = good["file"]
        for bad in ({"file": fid, "offset": -5}, {"file": fid, "offset": "1"}, {"file": fid, "offset": True},
                    {"file": fid, "offset": 1.5}, {"file": fid, "offset": None}, {"file": fid},
                    {"file": fid, "offset": 0, "last_status": 7}, {"file": fid.replace(":", "-"), "offset": 0},
                    {"file": " " + fid, "offset": 0}):
            lines, pos, info = self.read(bad)
            self.assertEqual((lines, info["read"], info["reset"]), ([], "ok", True), bad)
            self.assertEqual(pos, dict(good), bad)

    def test_same_file_but_offset_past_the_end_is_truncation(self):
        """ADV-8: 다른 프로세스가 더 앞선 위치를 써 두었어도 잘림으로 다룬다."""
        self.write("a\n")
        _, pos, _ = self.read(None)
        pos = dict(pos, offset=pos["offset"] + 999)
        lines, _, info = self.read(pos)
        self.assertEqual(lines, ["a"])
        self.assertTrue(info["reset"])

    def test_invalid_utf8_does_not_stop_reading(self):
        self.write("a\n")
        _, pos, _ = self.read(None)
        with open(self.path, "ab") as fh:
            fh.write(b"bad \xff\xfe bytes\nok\n")
        lines, _, _ = self.read(pos)
        self.assertEqual(lines[-1], "ok")
        self.assertEqual(len(lines), 2)


class TestWarpDaemonLogIsReadOnlyWhenAsked(unittest.TestCase):
    """AC-1(QA-1): VPN 감시가 켜져 있고 warp 가 공급자일 때만 읽는다. 아니면 열지도 않는다."""

    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    COLLECTORS = ("iface", "arp", "dhcp", "dns", "route", "wifi", "link")

    def engine(self, vpn_enabled, providers):
        from netmon.store import Store
        eng = Engine(configmod.load(os.path.join(self.d, "no-config.json")), Store(self.d))
        eng.cfg.set_feature("vpn.enabled", vpn_enabled)
        eng.cfg.set_feature("vpn.providers", providers)
        return eng

    def run_observe(self, eng):
        from netmon import engine as enginemod
        calls = []

        def spy(*a, **k):
            calls.append(1)
            return [], {"file": "1:1", "offset": 0, "last_status": None}, \
                {"read": "missing", "skipped_bytes": 0, "reset": True}
        with mock.patch.multiple(enginemod, **{n: mock.Mock(collect=(lambda ctx: {}))
                                               for n in self.COLLECTORS}), \
                mock.patch.object(vpnmod, "read_warp_daemon", side_effect=spy), \
                mock.patch.object(vpnmod, "collect", return_value={}), \
                mock.patch.object(vpnmod, "resolve",
                                  side_effect=lambda names: [p for p in vpnmod.ALL
                                                             if "auto" in names or p.name in names]):
            obs = eng.observe()
        return obs, calls

    def test_vpn_off_never_opens_the_log(self):
        obs, calls = self.run_observe(self.engine(False, ["warp"]))
        self.assertEqual(calls, [])
        self.assertNotIn("warp_daemon", obs.data)

    def test_warp_not_selected_never_opens_the_log(self):
        obs, calls = self.run_observe(self.engine(True, ["tailscale"]))
        self.assertEqual(calls, [])
        self.assertNotIn("warp_daemon", obs.data)

    def test_warp_selected_reads_the_log(self):
        obs, calls = self.run_observe(self.engine(True, ["warp"]))
        self.assertEqual(calls, [1])
        self.assertEqual(obs.data["warp_daemon"]["read"], "missing")
        self.assertEqual(obs.data["warp_daemon"]["lines"], [])


class TestWarpDaemonLogInTheEngine(unittest.TestCase):
    """엔진이 읽기를 어떻게 붙이는가 (DEV-2 — QA-2 재시작, AC-2 순서, QA-5 예외, K-6 `reset` 전달)."""

    COLLECTORS = TestWarpDaemonLogIsReadOnlyWhenAsked.COLLECTORS

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.log = os.path.join(self.d, "cfwarp_service_log.txt")
        with open(self.log, "w", encoding="utf-8") as fh:
            fh.write("old\n")
        self.calls = []

    def engine(self):
        from netmon.store import Store
        eng = Engine(configmod.load(os.path.join(self.d, "no-config.json")), Store(self.d))
        eng.cfg.set_feature("vpn.enabled", True)
        eng.cfg.set_feature("vpn.providers", ["warp"])
        return eng

    def observe(self, eng, read=None):
        from netmon import engine as enginemod
        real = vpnmod.read_warp_daemon

        def read_temp(pos, *a, **k):
            self.calls.append("read")
            return real(pos, path=self.log)

        def collect(providers):
            self.calls.append("collect")
            return {"warp": {"provider": "warp", "state": "connected"}}
        with mock.patch.multiple(enginemod, **{n: mock.Mock(collect=(lambda ctx: {}))
                                               for n in self.COLLECTORS}), \
                mock.patch.object(vpnmod, "read_warp_daemon", side_effect=read or read_temp), \
                mock.patch.object(vpnmod, "collect", side_effect=collect), \
                mock.patch.object(vpnmod, "resolve", side_effect=lambda names: [
                    p for p in vpnmod.ALL if p.name in names]):
            return eng.observe()

    def append(self, text):
        with open(self.log, "a", encoding="utf-8") as fh:
            fh.write(text)

    def test_a_restart_continues_from_the_position_in_state_json(self):
        eng = self.engine()
        self.assertTrue(self.observe(eng).data["warp_daemon"]["reset"])     # 처음 켬
        self.append("a\nb\n")
        self.assertFalse(self.observe(eng).data["warp_daemon"]["reset"])
        eng.store.save_state(eng.state)
        self.append("c\n")
        again = self.engine()                                             # 재시작
        self.assertIn(enginemod_pos_key(), again.state)
        wd = self.observe(again).data["warp_daemon"]
        self.assertEqual((wd["read"], wd["reset"]), ("ok", False))
        self.assertEqual(again.state[enginemod_pos_key()]["offset"], os.path.getsize(self.log))

    def test_the_log_is_read_after_the_vpn_query(self):
        self.observe(self.engine())
        self.assertEqual(self.calls, ["collect", "read"])

    def test_an_unexpected_exception_does_not_stop_the_cycle_and_leaves_no_message(self):
        def boom(*a, **k):
            raise RuntimeError("secret /opt/netmon-not-a-real-path/log")
        obs = self.observe(self.engine(), read=boom)
        self.assertEqual(obs.data["warp_daemon"]["read"], "unreadable")
        self.assertNotIn("secret", json.dumps(obs.data))
        self.assertIn("vpn", obs.data)

    def test_an_unexpected_exception_drops_the_position_and_marks_a_reset(self):
        """엔진은 예상 밖 예외 뒤 위치를 버리고 그 주기를 reset 으로 적는다 — 다음 주기는 처음 켬(끝에서 시작)이다."""
        eng = self.engine()
        self.observe(eng)
        self.assertIn(enginemod_pos_key(), eng.state)

        def boom(*a, **k):
            raise RuntimeError("x")
        obs = self.observe(eng, read=boom)
        self.assertTrue(obs.data["warp_daemon"]["reset"])
        self.assertNotIn(enginemod_pos_key(), eng.state)
        self.append("a\n")
        wd = self.observe(eng).data["warp_daemon"]
        self.assertTrue(wd["reset"])                     # 처음 켬 — 끝에서 시작해 옛 줄을 읽지 않는다

    def test_the_reset_flag_reaches_the_sample(self):
        for flag in (True, False):
            obs = self.observe(self.engine(), read=lambda pos, *a, **k: (
                [], {"file": "1:1", "offset": 0, "last_status": None},
                {"read": "ok", "skipped_bytes": 7, "reset": flag}))
            self.assertEqual((obs.data["warp_daemon"]["reset"], obs.data["warp_daemon"]["skipped_bytes"]), (flag, 7))


def enginemod_pos_key():
    from netmon import engine as enginemod
    return enginemod.WARP_DAEMON_POS_KEY


T0 = "2026-01-01T00:00:00.000Z"


def daemon_status(rest, ts=T0, pad=" "):
    return "%s%sDEBUG actor_ipc::logging: Ipc Broadcast ResponseStatus: %s" % (ts, pad, rest)


def daemon_disconnect(rest, ts=T0, level="WARN", module="main_loop", pad=" "):
    return "%s%s%s %s: warp::warp_service: Disconnecting due to %s" % (ts, pad, level, module, rest)


def daemon_error(rest, ts=T0, pad=" "):
    return ("%s%sWARN main_loop: warp::warp_service: Connection experienced runtime error error=%s"
            % (ts, pad, rest))


class TestWarpDaemonLineParsing(unittest.TestCase):
    """데몬 로그에서 쓰는 줄과 저장하는 모양 (DEV-3 — QA-3, QA-4, QA-5, ADV-1, ADV-2, ADV-3).

    쓰는 줄은 세 종류뿐이다: 상태 방송, 끊김 분류, 오류 원인. 줄 **맨 앞**의 시각·수준·모듈 경로·
    고정 문구가 모두 맞아야 한다. 상태는 이름만, 분류·오류는 주소·긴 16진을 도려내고 300자까지.
    같은 상태의 반복 방송은 저장하지 않는다(도려낸 뒤의 이름으로 비교).
    """

    def parse(self, lines, last=None):
        """(저장 줄 + 보류 줄, 마지막 상태, 해석 실패 수). 기준 상태가 `Connected`·모름이면 원인 줄은 저장되지 않고
        보류되므로(TODO K-1) 보류 줄도 함께 돌려준다 — "매칭되지 않는다" 는 시험이 보류로 헛통과하지 않게(DEV-9).
        보류와 저장을 가르는 시험은 `parse_warp_daemon` 을 직접 부른다."""
        kept, last, unparsed, held = vpnmod.parse_warp_daemon(lines, last)
        return kept + held, last, unparsed

    def cause(self, line):
        """열린 끊김 안(기준 상태가 비연결)에서 원인 줄 하나를 도려낸 글."""
        return self.parse([line], "Disconnected(X)")[0][0]["text"]

    def kinds(self, lines):
        return [(k["kind"], k["text"]) for k in self.parse(lines)[0]]

    # QA-3 ────────────────────────────────────────────────────────────────
    def test_three_kinds_with_level_padding_and_both_module_shapes(self):
        lines = [daemon_status("Connected {x}"),
                 daemon_status("Disconnected(InternalTunnelError)", pad="  "),
                 daemon_disconnect("runtime connection failure failure=Tunnel", pad="  "),
                 daemon_disconnect("settings change", level="INFO",
                                   module="main_loop:handle_update{update=SettingsChanged(..)}"),
                 daemon_error("TunnelError(SocketRecv(BrokenPipe))", pad="  ")]
        self.assertEqual(self.kinds(lines), [
            ("status", "Connected"), ("status", "Disconnected(InternalTunnelError)"),
            ("disconnect", "runtime connection failure failure=Tunnel"),
            ("disconnect", "settings change"),
            ("error", "TunnelError(SocketRecv(BrokenPipe))")])

    def test_continuation_lines_are_ignored_and_not_counted_as_failures(self):
        kept, last, unparsed = self.parse(["fl=abc", " changes=[x]", "", ") })}: captive_portal"])
        self.assertEqual((kept, last, unparsed), ([], None, 0))

    def test_other_timestamped_lines_are_not_stored(self):
        lines = [T0 + " DEBUG actor_ipc::dispatch: Ipc request: 00000000-0000-0000-0000-000000000000; GetDaemonStatus",
                 T0 + "  INFO main_loop: warp::warp_service: Disconnecting, but reason is unknown",
                 T0 + "  INFO main_loop{update=NetworkInfoChanged(..)}: warp::warp_service: Disconnecting due to x"]
        self.assertEqual(self.parse(lines), ([], None, 0))

    # QA-4 ────────────────────────────────────────────────────────────────
    def test_the_four_examples_of_the_spec(self):
        cases = [
            ("Connected {edge: 198.51.100.7:2408, source: Some(192.0.2.10)}", "Connected"),
            ('Disconnected(SettingsChanged { organization: "x", auth_client_secret: "y" })',
             "Disconnected(SettingsChanged)"),
            ("Connecting(PerformingHappyEyeballs(198.51.100.7:2408, [2001:db8::7]:2408))",
             "Connecting(PerformingHappyEyeballs)"),
            ("Unable(ConnectivityCheckFailed(Unknown))", "Unable(ConnectivityCheckFailed(Unknown))"),
        ]
        for rest, want in cases:
            self.assertEqual(self.kinds([daemon_status(rest)]), [("status", want)], rest)

    def test_a_name_followed_by_a_colon_or_a_dot_is_not_a_name(self):
        self.assertEqual(self.kinds([daemon_status("Connecting(fe80::1)")]), [("status", "Connecting")])
        self.assertEqual(self.kinds([daemon_status("Connecting(a.example)")]), [("status", "Connecting")])
        kept, _, unparsed = self.parse([daemon_status("fe80::1"), daemon_status("host.example")])
        self.assertEqual((kept, unparsed), ([], 2))

    def test_addresses_long_hex_and_length_are_cut_from_cause_lines(self):
        tail = ("failure to 198.51.100.7:2408 via [2001:db8::7]:443 and [192.0.2.1:53] key "
                "0123456789abcdef0123 " + "x" * 500)
        for line in (daemon_disconnect(tail), daemon_error(tail)):
            text = self.cause(line)
            for leak in ("198.51.100", "2001:db8", "192.0.2.1", "0123456789abcdef", ":2408", ":443", ":53"):
                self.assertNotIn(leak, text)
            self.assertIn("<addr>", text)
            self.assertIn("<hex>", text)
            self.assertLessEqual(len(text), vpnmod.WARP_DAEMON_TEXT_CAP)

    def test_repeated_broadcasts_are_not_stored_even_across_cycles(self):
        kept, last, _ = self.parse([daemon_status("Connected {a}"), daemon_status("Connected {b}"),
                                    daemon_status("Connecting(CheckingNetwork)"),
                                    daemon_status("Connecting(CheckingNetwork)")])
        self.assertEqual([k["text"] for k in kept], ["Connected", "Connecting(CheckingNetwork)"])
        kept, last, _ = self.parse([daemon_status("Connecting(CheckingNetwork {c})")], last)
        self.assertEqual((kept, last), ([], "Connecting(CheckingNetwork)"))

    def test_the_daemon_timestamp_is_kept_as_it_is(self):
        kept = self.parse([daemon_status("Connected", ts="2026-09-23T04:15:32.004Z")])[0]
        self.assertEqual(kept, [{"ts": "2026-09-23T04:15:32.004Z", "kind": "status", "text": "Connected"}])

    # QA-5 ────────────────────────────────────────────────────────────────
    def test_a_status_without_a_name_is_counted_and_nothing_is_kept(self):
        kept, last, unparsed = self.parse([daemon_status("{secret: 1}"), daemon_status(""),
                                           daemon_status("123"), daemon_status("[2001:db8::7]")])
        self.assertEqual((kept, last, unparsed), ([], None, 4))

    # ADV-1 ───────────────────────────────────────────────────────────────
    def test_the_phrases_in_the_middle_of_another_line_do_not_match(self):
        fake = "Ipc Broadcast ResponseStatus: Disconnected(Manual)"
        lines = [T0 + ' DEBUG warp::net: {"ssid":"x %s"}' % fake,
                 T0 + ' DEBUG warp::net: {"ssid":"a\\n%s"}' % daemon_status("Disconnected(Manual)"),
                 T0 + " INFO some::module: Disconnecting due to settings change",
                 T0 + " WARN other: Connection experienced runtime error error=x"]
        self.assertEqual(self.parse(lines), ([], None, 0))

    def test_a_forged_prefix_shorter_than_the_real_one_does_not_match(self):
        """고정 접두(상태 81·분류 82·오류 104바이트)에 못 미치는 조각은 줄 맨 앞에 와도 매칭되지 않는다.

        이보다 긴 문자열로 줄 맨 앞을 통째로 위조하는 것은 막지 않는다 — 네트워크가 정하는 문자열이
        날 개행과 함께 로그에 찍히는 경로를 모두 닫았다고 확인하지 못했다(docs/detections.md 의 한계).
        """
        for full, rx in ((daemon_status("Disconnected(Manual)"), vpnmod._RX_WARP_STATUS),
                         (daemon_disconnect("manual"), vpnmod._RX_WARP_DISCONNECT),
                         (daemon_error("x"), vpnmod._RX_WARP_ERROR)):
            head = full[:rx.match(full).end()]
            for n in range(len(head)):
                self.assertEqual(self.parse([head[:n]]), ([], None, 0), head[:n])

    def test_a_quoted_span_value_in_the_module_path_does_not_match(self):
        for module in ('main_loop:handle_update{update="manual user"}', "main_loop{reason=manual}",
                       "main_loop:handle_update{update=manual user(..)}",
                       "main_loop:handle_update{update=SettingsChanged(..)} user",
                       "main_loop:x"):
            line = daemon_disconnect("manual", level="INFO", module=module)
            self.assertEqual(self.parse([line]), ([], None, 0), module)

    def test_the_level_and_the_timestamp_must_be_exactly_the_observed_shape(self):
        lines = [T0 + " TRACE actor_ipc::logging: Ipc Broadcast ResponseStatus: Disconnected(X)",
                 T0 + " ERROR main_loop: warp::warp_service: Disconnecting due to x",
                 T0 + " INFO main_loop: warp::warp_service: Connection experienced runtime error error=x",
                 "2026-01-01T00:00:00Z DEBUG actor_ipc::logging: Ipc Broadcast ResponseStatus: Disconnected(X)",
                 "2026-01-01T00:00:00.1234Z DEBUG actor_ipc::logging: Ipc Broadcast ResponseStatus: Disconnected(X)",
                 "\uff12\uff10\uff12\uff16-01-01T00:00:00.000Z DEBUG actor_ipc::logging: Ipc Broadcast ResponseStatus: X"]
        self.assertEqual(self.parse(lines), ([], None, 0))

    def test_cutting_happens_after_scrubbing_so_nothing_is_split_at_an_edge(self):
        """앞쪽이 긴 16진 덩어리 하나로 줄어들어도, 그 뒤 어디에 걸친 주소·16진 값이든 조각으로 남지 않는다."""
        for value, leak in (("192.0.2.123", "192.0.2"), ("[2001:db8:1234:5678::9]:2408", "2001:db8"),
                            ("0123456789abcdef01234567", "0123456789")):
            for k in range(len(value) + 2):
                tail = "f" * (4096 - 1 - k) + " " + value + " rest"
                text = self.cause(daemon_error(tail))
                self.assertNotIn(leak, text, (value, k))

    def test_an_ipv6_with_an_embedded_ipv4_is_cut_whole(self):
        for v6 in ("2001:db8:1234:5678::192.0.2.1", "64:ff9b::198.51.100.7"):
            self.assertEqual(self.cause(daemon_error("to %s x" % v6)), "to <addr> x")
        self.assertEqual(self.cause(daemon_error("to :::192.0.2.1 x")), "to :::<addr> x")        # 유효하지 않은 앞부분
        self.assertEqual(self.cause(daemon_error("to 2001:db8::192.0.2.1:2408 x")), "to <addr> x")  # 포트는 도려냄

    def test_the_hex_and_port_boundaries(self):
        self.assertIn("<hex>", self.cause(daemon_error("key 0123456789abcdef end")))
        self.assertIn("0123456789abcde", self.cause(daemon_error("key 0123456789abcde end")))
        self.assertNotIn(":51820", self.cause(daemon_error("to 198.51.100.7:51820 end")))

    def test_control_characters_are_not_stored(self):
        text = self.cause(daemon_error("a\x1b[2Jb\x00c\x07d"))
        for ch in ("\x1b", "\x00", "\x07"):
            self.assertNotIn(ch, text)

    # ADV-2 ───────────────────────────────────────────────────────────────
    def test_brackets_that_do_not_start_with_a_name_are_dropped(self):
        for rest in ("Connecting(123abc)", "Connecting(198.51.100.7:2408)", "Connecting([2001:db8::7]:2408)",
                     "Connecting(fe80::1)", "Connecting(a.example)", "Connecting(abc:def)",
                     'Connecting("quoted")', "Connected {Disconnected(Manual)}"):
            want = "Connected" if rest.startswith("Connected") else "Connecting"
            self.assertEqual(self.kinds([daemon_status(rest)]), [("status", want)], rest)
        self.assertEqual(self.kinds([daemon_status("Connecting(Performing(fe80::1))")]),
                         [("status", "Connecting(Performing)")])

    def test_a_half_written_last_line_never_becomes_a_state(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, "log")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("x\n")
        _, pos, _ = vpnmod.read_warp_daemon(None, path=path)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(daemon_status("Connected") + "\n" + daemon_status("Conn"))
        lines, pos, _ = vpnmod.read_warp_daemon(pos, path=path)
        self.assertEqual(self.kinds(lines), [("status", "Connected")])

    # ADV-3 ───────────────────────────────────────────────────────────────
    def test_huge_and_broken_lines_finish_quickly_and_keep_nothing_extra(self):
        import time
        config = "Disconnected(SettingsChanged { " + 'organization: "x", ' * 1500 + "})"
        cases = [
            (daemon_status(config), [("status", "Disconnected(SettingsChanged)")], 0),
            (daemon_status("A" * (1 << 20)), [], 1),
            (daemon_status("A(" * 5000), None, 0),
            (daemon_disconnect("1:" * (1 << 19)), None, 0),
            (daemon_error("[" * (1 << 20)), None, 0),
            (daemon_status("Connected��"), [], 1),
            (daemon_status("Conn�ected"), [], 1),
        ]
        for line, want, unparsed in cases:
            start = time.time()
            kept, _, n = self.parse([line])
            self.assertLess(time.time() - start, 2.0, line[:60])
            self.assertEqual(n, unparsed, line[:60])
            for k in kept:
                self.assertLessEqual(len(k["text"]), vpnmod.WARP_DAEMON_TEXT_CAP)
            if want is not None:
                self.assertEqual([(k["kind"], k["text"]) for k in kept], want, line[:60])

    # DEV-9 (DEV-3 2회차 검수 [낮음]) ────────────────────────────────────────
    def test_every_kind_requires_its_module_path(self):
        lines = [T0 + " DEBUG warp::net: Ipc Broadcast ResponseStatus: Disconnected(X)",
                 T0 + " DEBUG actor_ipc::other: Ipc Broadcast ResponseStatus: Disconnected(X)",
                 T0 + " WARN other::mod: warp::warp_service: Connection experienced runtime error error=x",
                 T0 + " WARN main_loop: other::svc: Connection experienced runtime error error=x",
                 T0 + " WARN main_loop:x: warp::warp_service: Connection experienced runtime error error=x",
                 T0 + " INFO main_loop:handle_update{update=SettingsChanged(x)}: warp::warp_service: Disconnecting due to x",
                 T0 + " INFO main_loop:handle_update{update=SettingsChanged(...)}: warp::warp_service: Disconnecting due to x",
                 T0 + " INFO main_loop: other::svc: Disconnecting due to x"]
        for last in (None, "Connected", "Disconnected(X)"):
            self.assertEqual(self.parse(lines, last), ([], last, 0), last)

    def test_cause_lines_take_only_ascii_digits_in_the_timestamp(self):
        wide = "\uff12\uff10\uff12\uff16-01-01T00:00:00.000Z"
        arabic = "\u0662\u0660\u0662\u0666-01-01T00:00:00.000Z"
        for ts in (wide, arabic):
            lines = [ts + " WARN main_loop: warp::warp_service: Disconnecting due to x",
                     ts + " WARN main_loop: warp::warp_service: Connection experienced runtime error error=x"]
            self.assertEqual(self.parse(lines, "Disconnected(X)"), ([], "Disconnected(X)", 0), ts)

    def test_a_brace_right_after_a_name_ends_it(self):
        self.assertEqual(self.kinds([daemon_status("Connected{x}")]), [("status", "Connected")])

    def test_screen_control_characters_become_question_marks(self):
        for ch in ("\x00", "\x1b", "\x7f", "\x80", "\x9b", "\x9f", "\u2028", "\u2029", "\u200b", "\u200e", "\u200f",
                   "\u202a", "\u202e", "\u2066", "\u2069", "\ufeff", "\u00ad", "\u061c", "\u2060", "\U000e0041"):
            self.assertEqual(self.cause(daemon_error("a" + ch + "b")), "a?b", repr(ch))
        for ch in ("\u00a0", "\u00e9", "\u4e00", "\u2030"):          # 제어 문자가 아닌 것은 그대로
            self.assertEqual(self.cause(daemon_error("a" + ch + "b")), "a" + ch + "b", repr(ch))

    def test_a_name_with_a_long_hex_run_is_not_a_name(self):
        """16자 이상 16진 덩어리를 품은 이름은 이름이 아니다 — 전부 16진인 이름만 거르던 것을 분류·오류 줄의 16진 규칙과 같게(DEV-9)."""
        self.assertEqual(self.kinds([daemon_status("Connecting(k0123456789abcdef0123456789abcdef)")]),
                         [("status", "Connecting")])
        self.assertEqual(self.kinds([daemon_status("Unable(Key(x0123456789abcdef0123456789abcdef))")]),
                         [("status", "Unable(Key)")])
        self.assertEqual(self.parse([daemon_status("Connected0123456789abcdef0123")]), ([], None, 1))
        self.assertEqual(self.kinds([daemon_status("Connecting(PerformingHappyEyeballs)")]),
                         [("status", "Connecting(PerformingHappyEyeballs)")])
        self.assertEqual(self.kinds([daemon_status("Connecting(Deadbeefdeadbee)")]),        # 15자는 이름
                         [("status", "Connecting(Deadbeefdeadbee)")])

    def test_name_edges_length_depth_and_hex(self):
        self.assertEqual(self.kinds([daemon_status("Connecting(abc-def)")]), [("status", "Connecting")])
        self.assertEqual(self.kinds([daemon_status("Connecting(Abc,Def)")]), [("status", "Connecting(Abc)")])
        self.assertEqual(self.kinds([daemon_status("Z" * 64)]), [("status", "Z" * 64)])
        self.assertEqual(self.parse([daemon_status("Z" * 65)])[2], 1)
        self.assertEqual(self.kinds([daemon_status("A(B(C(D(E))))")]), [("status", "A(B(C(D)))")])
        # 16자 이상이 전부 16진이면 이름이 아니다(주소·키 조각) — 15자까지는 이름
        self.assertEqual(self.kinds([daemon_status("Connecting(deadbeefdeadbeef)")]), [("status", "Connecting")])
        self.assertEqual(self.parse([daemon_status("deadbeefdeadbeef00")])[2], 1)
        self.assertEqual(self.kinds([daemon_status("Connecting(Deadbeefdeadbee)")]),
                         [("status", "Connecting(Deadbeefdeadbee)")])

    def test_nesting_is_bounded(self):
        kept = self.parse([daemon_status("A(" * 5000)])[0]
        self.assertEqual(kept[0]["text"].count("("), vpnmod.WARP_STATUS_DEPTH - 1)


class TestWarpDaemonLinesInTheSample(unittest.TestCase):
    """엔진이 표본 `data.warp_daemon` 에 도려낸 줄만 싣는다 (DEV-3 — QA-4, QA-5, QA-10)."""

    COLLECTORS = TestWarpDaemonLogIsReadOnlyWhenAsked.COLLECTORS

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        from netmon.store import Store
        self.eng = Engine(configmod.load(os.path.join(self.d, "no-config.json")), Store(self.d))
        self.eng.cfg.set_feature("vpn.enabled", True)
        self.eng.cfg.set_feature("vpn.providers", ["warp"])

    def observe(self, lines, parse=None):
        from netmon import engine as enginemod

        def read(pos, *a, **k):
            last = pos.get("last_status") if isinstance(pos, dict) else None
            return list(lines), {"file": "1:1", "offset": 10, "last_status": last}, \
                {"read": "ok", "skipped_bytes": 0, "reset": False}
        patches = [mock.patch.multiple(enginemod, **{n: mock.Mock(collect=(lambda ctx: {}))
                                                     for n in self.COLLECTORS}),
                   mock.patch.object(vpnmod, "read_warp_daemon", side_effect=read),
                   mock.patch.object(vpnmod, "collect",
                                     return_value={"warp": {"provider": "warp", "state": "connected"}}),
                   mock.patch.object(vpnmod, "resolve", side_effect=lambda names: [
                       p for p in vpnmod.ALL if p.name in names])]
        if parse is not None:
            patches.append(mock.patch.object(vpnmod, "parse_warp_daemon", side_effect=parse))
        with contextlib.ExitStack() as st:
            for p in patches:
                st.enter_context(p)
            return self.eng.observe()

    def test_kept_lines_state_and_counts(self):
        obs = self.observe([daemon_status("Connected {edge: 198.51.100.7:2408}"),
                            daemon_status("Disconnected(InternalTunnelError)", ts="2026-01-01T00:00:01.000Z"),
                            daemon_status("123")])
        wd = obs.data["warp_daemon"]
        self.assertEqual(wd["lines"], [
            {"ts": T0, "kind": "status", "text": "Connected"},
            {"ts": "2026-01-01T00:00:01.000Z", "kind": "status", "text": "Disconnected(InternalTunnelError)"}])
        self.assertEqual((wd["state"], wd["unparsed"], wd["read"]), ("Disconnected(InternalTunnelError)", 1, "ok"))
        self.assertNotIn("198.51.100", json.dumps(obs.data))

    def test_the_comparison_state_is_kept_with_the_position(self):
        self.observe([daemon_status("Connected")])
        self.assertEqual(self.eng.state[enginemod_pos_key()]["last_status"], "Connected")
        obs = self.observe([daemon_status("Connected {again}")])
        self.assertEqual((obs.data["warp_daemon"]["lines"], obs.data["warp_daemon"]["state"]), ([], "Connected"))

    def test_the_lines_do_not_go_into_the_provider_dict(self):
        obs = self.observe([daemon_status("Disconnected(Manual)")])
        self.assertEqual(set(obs.data["vpn"]["warp"]), {"provider", "state"})

    def test_a_parse_exception_leaves_no_message_and_does_not_stop_the_cycle(self):
        def boom(*a, **k):
            raise ValueError("secret /opt/netmon-not-a-real-path/log")
        self.observe([daemon_status("Connected")])
        obs = self.observe([daemon_status("Connected")], parse=boom)
        wd = obs.data["warp_daemon"]
        self.assertEqual((wd["read"], wd["lines"], wd["reset"]), ("unreadable", [], True))
        self.assertNotIn("secret", json.dumps(obs.data))
        self.assertNotIn(enginemod_pos_key(), self.eng.state)    # 같은 구간을 되읽어 매 주기 실패하지 않게

    def test_a_comparison_state_that_is_not_a_status_name_is_not_trusted(self):
        """state.json 의 `last_status` 가 이름 문법에 맞지 않으면 모름으로 본다(표본 `state` 로 새지 않게)."""
        from netmon import engine as enginemod
        self.eng.state[enginemod.WARP_DAEMON_POS_KEY] = {"file": "1:1", "offset": 10,
                                                         "last_status": "Connected {organization: x}"}
        real_read = vpnmod.read_warp_daemon
        with mock.patch.object(vpnmod, "read_warp_daemon",
                               side_effect=lambda pos, *a, **k: real_read(pos, path="/opt/netmon-not-a-real-path")):
            wd = self.eng._read_warp_daemon()
        self.assertIsNone(wd["state"])


    # DEV-4 3회차: 수집 쪽 보류(TODO K-1)와 첫 읽기 표지(K-8) ─────────────────────
    def at(self, sec):
        return "2026-01-01T00:00:%sZ" % sec

    def held(self):
        return self.eng.state[enginemod_pos_key()].get("held")

    def test_cause_lines_seen_while_connected_wait_for_the_next_broadcast(self):
        self.observe([daemon_status("Connected", ts=self.at("00.000"))])
        obs = self.observe([daemon_disconnect("settings change", ts=self.at("05.000"))])
        self.assertEqual(obs.data["warp_daemon"]["lines"], [])                # 아직 저장하지 않는다
        self.assertEqual([x["text"] for x in self.held()], ["settings change"])
        obs = self.observe([daemon_status("Connected {again}", ts=self.at("05.001"))])
        self.assertEqual((obs.data["warp_daemon"]["lines"], self.held()), ([], []))   # 반복 방송이 답함 → 버림
        self.observe([daemon_error("TunnelError(x)", ts=self.at("06.000"))])
        obs = self.observe([daemon_status("Disconnected(InternalTunnelError)", ts=self.at("06.001"))])
        self.assertEqual([(x["kind"], x["text"]) for x in obs.data["warp_daemon"]["lines"]],
                         [("error", "TunnelError(x)"), ("status", "Disconnected(InternalTunnelError)")])
        obs = self.observe([daemon_disconnect("x", ts=self.at("07.000"))])       # 비연결 상태 — 바로 저장
        self.assertEqual([x["kind"] for x in obs.data["warp_daemon"]["lines"]], ["disconnect"])
        self.assertEqual(self.held(), [])

    def test_cause_lines_seen_while_the_state_is_unknown_are_held_too(self):
        """DEV-14: 기준 상태를 모를 때(처음 켬·연속성이 끊긴 뒤)도 원인 줄은 보류한다(TODO K-1 — 연결과 같게)."""
        kept, last, _, held = vpnmod.parse_warp_daemon([daemon_disconnect("settings change", ts=self.at("01.000"))], None)
        self.assertEqual((kept, last), ([], None))
        self.assertEqual([x["text"] for x in held], ["settings change"])
        kept, last, _, held = vpnmod.parse_warp_daemon([daemon_status("Connected", ts=self.at("01.001"))], None, held)
        self.assertEqual([x["kind"] for x in kept], ["disconnect", "status"])      # 모름 → Connected 는 바뀐 방송
        self.assertEqual(held, [])

    def test_the_hold_is_capped(self):
        self.observe([daemon_status("Connected", ts=self.at("00.000"))])
        self.observe([daemon_error("e%d" % i, ts=self.at("01.%03d" % i)) for i in range(50)])
        self.assertEqual(len(self.held()), vpnmod.WARP_DAEMON_HELD_MAX)
        self.assertEqual(self.held()[-1]["text"], "e49")

    def test_a_tampered_hold_in_the_state_file_is_not_published(self):
        from netmon import engine as enginemod
        good = {"ts": T0, "kind": "error", "text": "fine"}
        self.eng.state[enginemod.WARP_DAEMON_POS_KEY] = {
            "file": "1:1", "offset": 10, "last_status": "Connected",
            "held": [dict(good)] * 3 + [
                {"ts": T0, "kind": "error", "text": "to 198.51.100.7 x"},     # 도려내지 않은 글
                {"ts": T0, "kind": "error", "text": "k " + "ab" * 12},        # 도려내지 않은 긴 16진
                {"ts": "yesterday", "kind": "error", "text": "a"},
                {"ts": T0, "kind": "status", "text": "Connected"},
                {"ts": T0, "kind": "error", "text": "b", "extra": 1},
                "x", 5]}
        obs = self.observe([daemon_status("Disconnected(X)", ts=self.at("01.000"))])
        lines = obs.data["warp_daemon"]["lines"]
        self.assertNotIn("198.51.100", json.dumps(obs.data))
        self.assertNotIn("abab", json.dumps(obs.data))
        self.assertEqual(lines[:-1], [good] * 3)
        self.assertEqual(lines[-1]["text"], "Disconnected(X)")
        self.eng.state[enginemod.WARP_DAEMON_POS_KEY].update(last_status="Connected", held=[dict(good)] * 30)
        obs = self.observe([daemon_status("Disconnected(Y)", ts=self.at("01.500"))])
        self.assertEqual(obs.data["warp_daemon"]["lines"][:-1], [good] * vpnmod.WARP_DAEMON_HELD_MAX)
        self.eng.state[enginemod.WARP_DAEMON_POS_KEY]["held"] = "not a list"
        self.observe([daemon_status("Connected", ts=self.at("02.000"))])

    def test_a_break_in_continuity_drops_the_hold_with_the_comparison_state(self):
        self.observe([daemon_status("Connected", ts=self.at("00.000"))])
        self.observe([daemon_disconnect("settings change", ts=self.at("05.000"))])
        from netmon import engine as enginemod

        def reset_read(pos, *a, **k):
            return [daemon_status("Disconnected(X)", ts=self.at("09.000"))], \
                {"file": "2:2", "offset": 0, "last_status": None}, {"read": "ok", "skipped_bytes": 0, "reset": True}
        with mock.patch.object(vpnmod, "read_warp_daemon", side_effect=reset_read):
            wd = self.eng._read_warp_daemon()
        self.assertEqual([x["kind"] for x in wd["lines"]], ["status"])      # 끊긴 너머의 원인 줄을 붙이지 않는다
        self.assertEqual(self.eng.state[enginemod.WARP_DAEMON_POS_KEY]["held"], [])

    def test_a_held_line_with_a_trailing_newline_in_its_time_is_not_published(self):
        """DEV-13: 시각 검증이 끝 개행(`…000Z\\n`)을 받지 않는다 — 조작된 보류 줄이 표본에 개행째 실리지 않게."""
        self.assertEqual(vpnmod.valid_held([{"ts": T0 + "\n", "kind": "error", "text": "x"}]), [])
        self.assertEqual(vpnmod.valid_held([{"ts": T0, "kind": "error", "text": "x"}]),
                         [{"ts": T0, "kind": "error", "text": "x"}])

    def test_only_the_first_read_of_a_process_is_marked(self):
        first = self.observe([daemon_status("Connected")]).data["warp_daemon"]
        second = self.observe([]).data["warp_daemon"]
        self.assertIs(first.get("process_start"), True)
        self.assertNotIn("process_start", second)


def dl(ts, kind, text):
    """저장된 데몬 줄 하나(`data.warp_daemon.lines` 의 모양)."""
    return {"ts": "2026-01-01T00:00:%sZ" % ts, "kind": kind, "text": text}


class _DaemonSequence:
    """데몬 로그 판정 시험의 공통 도우미. 표본 ts 는 5초 간격, 데몬 줄 시각은 밀리초까지."""

    DROP = [dl("07.490", "error", "TunnelError(SocketRecv(BrokenPipe))"),
            dl("07.491", "disconnect", "runtime connection failure failure=Tunnel"),
            dl("07.493", "status", "Disconnected(InternalTunnelError)"),
            dl("08.100", "status", "Connecting(CheckingNetwork)"),
            dl("09.004", "status", "Connected")]

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.cfg = configmod.load(os.path.join(self.d, "config.json"))

    def o(self, sec, lines=(), state="connected", reset=False, link=True, read="ok", start=False, **kw):
        """`start` 는 이 표본이 프로세스의 첫 읽기라는 표지(`process_start`, TODO K-8)다 — 실제 수집에서는
        새 엔진 인스턴스의 첫 `_read_warp_daemon` 이 남긴다."""
        kw.setdefault("security", "WPA2_PSK")
        ob = obs(ts="2026-01-01T00:%02d:%02dZ" % divmod(sec, 60), vpn=vpn_state(state), **kw)
        if not link:
            ob.data["iface"]["primary"] = None
        ob.data["warp_daemon"] = {"read": read, "lines": [dict(x) for x in lines], "state": None,
                                  "skipped_bytes": 0, "unparsed": 0, "reset": reset}
        if start:
            ob.data["warp_daemon"]["process_start"] = True
        return ob

    def start(self):
        """첫 주기(데몬 상태를 모르고 조회가 하나뿐이라 새 판정 없음)와 상태를 아는 둘째 주기."""
        return [self.o(0, [dl("00.000", "status", "Connected")]), self.o(5)]

    def run_seq(self, seq):
        res = enginemod_replay(self.cfg, seq)
        self.assertEqual([f.summary for _, fs in res for f in fs if f.kind == "DETECTOR_ERROR"], [])
        # AC-17: 데몬 로그로만 잡힌 판정은 어느 열에서든 '의심'이다 — 링크 없는 주기의 끊김, 한 창의 여러 끊김, 창당 상한,
        # 귀속이 붙은 주기 같은 경계 사례를 이 도우미를 쓰는 시험 전부가 함께 고정한다(DEV-16 1회차 검수 [낮음]).
        self.assertEqual({f.confidence for _, fs in res for f in fs if f.evidence.get("timing_source") == "daemon"} - {"suspect"},
                         set())
        return res

    def daemon_kinds(self, results, i):
        return [f.kind for f in results[i][1] if f.evidence.get("timing_source") == "daemon"]

    def engine(self, state):
        """새 엔진 인스턴스(재시작). 재시작 뒤 첫 판정 주기의 억제는 표본의 `process_start` 로 준다(`o(start=True)`)."""
        from netmon import investigate
        eng = Engine.__new__(Engine)
        eng.cfg, eng.state, eng.store = self.cfg, state, None
        eng.prev = eng.anchor = eng.prev_wall = None
        eng.link_gap = False
        eng._baseline_saved_at = eng._arp_log_read_at = None
        eng.investigator = investigate.Investigator(None)
        eng.needs = {}
        return eng

    def judge_seq(self, eng, seq):
        out = []
        for ob in seq:
            out.append(eng.judge(ob, 5.0))
            eng.prev = ob
        return out


class TestShortDropsFromTheDaemonLog(_DaemonSequence, unittest.TestCase):
    """조회 사이에 끝난 WARP 끊김을 데몬 로그로 판정한다 (DEV-4 — QA-6, QA-14, QA-10, ADV-6, ADV-7).

    관측 열을 `replay` 로 돌린다 — 판정은 관측의 `data.warp_daemon` 과 상태 dict 만 읽는다.
    표본 ts 는 5초 간격, 데몬 줄 시각은 밀리초까지.
    """
    # QA-6 ────────────────────────────────────────────────────────────────
    def test_a_drop_between_polls_gives_three_findings_in_order(self):
        res = self.run_seq(self.start() + [self.o(10, self.DROP)])
        self.assertEqual([f.kind for f in res[2][1] if f.kind.startswith("VPN_")],
                         ["VPN_DISCONNECTED", "VPN_PROTECTION_LOST", "VPN_RECONNECTED"])
        d, p, r = [f for f in res[2][1] if f.kind.startswith("VPN_")]
        self.assertEqual((d.severity, d.attribution), ("info", "vpn_change"))
        self.assertEqual(d.evidence["provider_state"], "disconnected")
        self.assertEqual(d.evidence["provider_reason"], "runtime connection failure failure=Tunnel")
        self.assertEqual((d.evidence["daemon_down_at"], d.evidence["daemon_up_at"]),
                         ("2026-01-01T00:00:07.493Z", "2026-01-01T00:00:09.004Z"))
        self.assertEqual(d.evidence["daemon_read"], "ok")
        self.assertEqual([x["kind"] for x in d.evidence["daemon_lines"]],
                         ["error", "disconnect", "status", "status", "status"])
        for key in ("first_hop_method", "first_hop_alive"):
            self.assertNotIn(key, d.evidence)
        self.assertEqual(set(p.evidence), {"provider", "wifi_security", "security_kind",
                                           "passively_readable", "user_action", "timing_source"})
        self.assertEqual((p.severity, p.attribution, p.evidence["user_action"]), ("info", None, False))
        self.assertEqual(r.severity, "info")
        self.assertEqual(r.evidence["down_since"], "2026-01-01T00:00:07Z")
        self.assertEqual(r.evidence["down_seconds"], 1.5)       # 조회 경로와 같이 0.1초 단위(밀리초는 daemon_*_at)
        self.assertEqual((r.evidence["unmeasured_seconds"], r.evidence["prev_state"]), (0.0, "connecting"))
        self.assertIsNone(r.attribution)
        self.assertEqual(d.summary, msg.VPN_DISCONNECTED_BETWEEN_POLLS
                         % ("warp", msg.DUR_SECONDS % 2) + " " + msg.VPN_DAEMON_REASON % "InternalTunnelError")

    def test_the_daemon_path_never_reads_manual_or_user_as_a_user_action(self):
        drop = [dl("07.491", "disconnect", "manual user disabled_by_user stopped"),
                dl("07.493", "status", "Disconnected(Manual)"), dl("09.004", "status", "Connected")]
        res = self.run_seq(self.start() + [self.o(10, drop)])
        d, p, r = [f for f in res[2][1] if f.kind.startswith("VPN_")]
        self.assertEqual((d.severity, d.attribution), ("info", "vpn_change"))
        self.assertEqual((p.severity, p.attribution, p.evidence["user_action"]), ("info", None, False))

    def test_the_daemon_path_opens_no_investigation(self):
        res = self.run_seq(self.start() + [self.o(10, self.DROP)] + [self.o(15 + 5 * i) for i in range(6)])
        self.assertFalse([f.kind for _, fs in res for f in fs if f.kind.startswith("INVESTIGATION")])

    def test_the_daemon_path_opens_no_investigation_even_with_attributed_included(self):
        """AC-16(DEV-15): 새 경로 끊김은 귀속이 늘 붙어(`vpn_change` 기본) 기본 규칙에서는 조사를 열지 않지만, 조사 설정
        `include_attributed` 를 켜면 수정 전에는 `vpn_drop` 을 열었다 — 실제 판정기 출력으로 고정한다(DEV-15 검수 1회차)."""
        self.cfg.data["investigate"] = {"open_on": {"include_attributed": True}}
        res = self.run_seq(self.start() + [self.o(10, self.DROP)] + [self.o(15 + 5 * i) for i in range(6)])
        self.assertEqual(self.daemon_kinds(res, 2), ["VPN_DISCONNECTED", "VPN_PROTECTION_LOST", "VPN_RECONNECTED"])
        self.assertFalse([f.kind for _, fs in res for f in fs if f.kind.startswith("INVESTIGATION")])

    def test_a_drop_the_poll_saw_gets_nothing_from_this_path(self):
        seqs = [
            # 창 N 에서 열리고 N+1 에서 닫힘, 조회는 비연결 → 연결
            self.start() + [self.o(10, self.DROP[:3], state="disconnected"), self.o(15, self.DROP[3:])],
            # 링크 없는 주기의 조회가 비연결
            self.start() + [self.o(10, self.DROP[:3], state="disconnected", link=False),
                            self.o(15, self.DROP[3:])],
        ]
        for seq in seqs:
            res = self.run_seq(seq)
            self.assertEqual([k for i in range(len(res)) for k in self.daemon_kinds(res, i)], [])

    def test_the_daemon_path_findings_are_suspect_and_the_poll_path_stays_confirmed(self):
        """AC-17(사용자 결정 2026-09-27): 데몬 로그로만 잡힌 세 판정의 확신도는 '의심' — 줄 맨 앞 위조를 막지 못한 경로라 양성 오류의
        여지가 있다. 조회 경로(조회로 잡힌 끊김·보호 상실·복구, 링크 없는 주기의 끊김)는 '확정' 그대로이고 등급도 그대로다."""
        res = self.run_seq(self.start() + [self.o(10, self.DROP)])
        daemon = [f for f in res[2][1] if f.evidence.get("timing_source") == "daemon"]
        self.assertEqual([(f.kind, f.confidence, f.severity) for f in daemon],
                         [("VPN_DISCONNECTED", "suspect", "info"), ("VPN_PROTECTION_LOST", "suspect", "info"),
                          ("VPN_RECONNECTED", "suspect", "info")])
        kinds = ("VPN_DISCONNECTED", "VPN_PROTECTION_LOST", "VPN_RECONNECTED")
        for label, seq, want in (
                ("조회 경로", self.start() + [self.o(10, self.DROP[:3], state="disconnected"), self.o(15, self.DROP[3:])], kinds),
                ("링크 없는 주기", self.start() + [self.o(10, self.DROP[:3], state="disconnected", link=False),
                                                self.o(15, self.DROP[3:])], ("VPN_DISCONNECTED", "VPN_RECONNECTED"))):
            poll = [f for _, fs in self.run_seq(seq) for f in fs if f.kind in kinds]
            self.assertEqual(sorted({f.kind for f in poll}), sorted(want), label)
            self.assertEqual({(f.confidence, f.evidence.get("timing_source")) for f in poll}, {("confirmed", None)}, label)
        self.assertEqual({f.severity for _, fs in self.run_seq(self.start() + [self.o(10, self.DROP[:3], state="disconnected"),
                                                                             self.o(15, self.DROP[3:])])
                          for f in fs if f.kind == "VPN_PROTECTION_LOST"}, {"medium"})

    def test_the_daemon_path_follows_the_same_rules_on_every_kind_of_network(self):
        """AC-6·AC-17: 데몬 경로 세 판정은 네트워크 암호화 방식과 무관하게 '의심'·info 이고, 보호 상실은 조회 경로와 같은 규칙으로
        내거나(개방형·SAE·방식 모름) 내지 않는다(개인별 자격증명). 다른 데몬 시험은 WPA2 개인(공유 비밀번호) 하나로만 돌아, 다른
        갈래의 확신도·등급·발생 여부를 고정하지 않았다(DEV-16 2회차 검수 [낮음] X5, [범위 밖] Y1·Y2)."""
        three = ["VPN_DISCONNECTED", "VPN_PROTECTION_LOST", "VPN_RECONNECTED"]
        for security, kinds in (("none", three), ("WPA3_SAE", three), (None, three),
                                ("WPA2_Enterprise", ["VPN_DISCONNECTED", "VPN_RECONNECTED"])):
            seq = [self.o(0, [dl("00.000", "status", "Connected")], security=security), self.o(5, security=security),
                   self.o(10, self.DROP, security=security)]
            res = self.run_seq(seq)
            got = [(f.kind, f.confidence, f.severity) for f in res[2][1] if f.evidence.get("timing_source") == "daemon"]
            self.assertEqual(got, [(k, "suspect", "info") for k in kinds], security)

    def test_the_protection_loss_confidence_depends_only_on_the_path(self):
        """AC-17: 보호 상실의 확신도는 경로로만 갈린다 — `_protection_lost` 가 가르는 갈래(이번 관측의 암호화 방식 다섯, 직접 끊음
        여부, 재협상 중 머리, 직전 관측 유무)의 곱에서 조회 경로(인자 없는 호출)는 `confirmed`·등급 규칙대로, 데몬 경로(등급 info·확신도
        suspect 를 넘긴 호출)는 `suspect`·info. 개인별 자격증명이면 둘 다 내지 않는다. 두 경로가 같은 함수를 쓰므로 확신도를 이 갈래에
        걸어 바꾸는 변이를 잡는다(DEV-16 3회차 검수 [낮음]). 직전 관측이 다른 암호화 방식을 채우는 경우·유선·인터페이스 바뀜은 바꾸지
        않는다 — 확신도는 그 입력으로 갈리지 않는다(4회차 검수 [정보])."""
        want_sev = {"none": ("low", "medium"), "WPA2_PSK": ("low", "medium"), "WPA3_SAE": ("low", "low"), None: ("low", "low")}
        for security in ("none", "WPA2_PSK", "WPA3_SAE", None, "WPA2_Enterprise"):
            cur = obs(security=security)
            for user, now, prev in itertools.product((True, False), ("disconnected", "connecting"), (None, cur)):
                case = (security, user, now, prev is None)
                poll = vpn_rules._protection_lost("warp", now, cur, prev, user)
                daemon = vpn_rules._protection_lost("warp", now, cur, prev, user, {"timing_source": "daemon"},
                                                    severity="info", confidence="suspect")
                if security == "WPA2_Enterprise":
                    self.assertEqual((poll, daemon), ([], []), case)
                    continue
                self.assertEqual([(f.confidence, f.severity) for f in poll], [("confirmed", want_sev[security][0 if user else 1])],
                                 case)
                self.assertEqual([(f.confidence, f.severity) for f in daemon], [("suspect", "info")], case)

    def test_a_drop_across_a_window_boundary_counts_once(self):
        res = self.run_seq(self.start() + [self.o(10, self.DROP[:3]), self.o(15, self.DROP[3:])])
        self.assertEqual(self.daemon_kinds(res, 2), [])
        self.assertEqual(self.daemon_kinds(res, 3), ["VPN_DISCONNECTED", "VPN_PROTECTION_LOST", "VPN_RECONNECTED"])

    def test_two_drops_in_one_window_give_two_sets(self):
        second = [dl("11.000", "status", "Connecting(CheckingNetwork)"), dl("12.000", "status", "Connected")]
        res = self.run_seq(self.start() + [self.o(15, self.DROP + second)])
        self.assertEqual(self.daemon_kinds(res, 2), ["VPN_DISCONNECTED", "VPN_PROTECTION_LOST", "VPN_RECONNECTED"] * 2)
        second_d = [f for f in res[2][1] if f.kind == "VPN_DISCONNECTED"][1]
        self.assertEqual(second_d.summary, msg.VPN_RENEGOTIATING_BETWEEN_POLLS % ("warp", msg.DUR_SECONDS % 1))

    def test_no_new_findings_on_a_gap_a_restart_an_unknown_state_or_a_carried_gap(self):
        cases = {
            "측정 공백": self.start() + [self.o(100, self.DROP)],
            "처음 켠 첫 주기": [self.o(0, [dl("00.000", "status", "Connected")] + self.DROP)],
            "재시작 첫 주기": self.start() + [self.o(10, self.DROP, start=True)],
            "상태 모름": [self.o(0), self.o(5, self.DROP[2:])],
            "넘어온 창의 공백": self.start() + [self.o(100, self.DROP, link=False), self.o(105)],
            "연속성이 끊긴 주기": self.start() + [self.o(10, self.DROP[2:], reset=True)],
        }
        for name, seq in cases.items():
            res = self.run_seq(seq)
            self.assertEqual([k for i in range(len(res)) for k in self.daemon_kinds(res, i)], [], name)

    def test_a_window_from_a_cycle_without_a_link_is_judged_in_the_next_judged_cycle(self):
        res = self.run_seq(self.start() + [self.o(10, self.DROP, link=False), self.o(15)])
        self.assertEqual(self.daemon_kinds(res, 2), [])
        # 링크 없는 주기에 시작한 끊김이라 보호 상실은 없다(K-3, DEV-4 3회차)
        self.assertEqual(self.daemon_kinds(res, 3), ["VPN_DISCONNECTED", "VPN_RECONNECTED"])

    def test_a_drop_that_starts_renegotiating_has_the_renegotiating_head(self):
        drop = [dl("07.493", "status", "Connecting(PerformingHappyEyeballs)"), dl("09.004", "status", "Connected")]
        res = self.run_seq(self.start() + [self.o(10, drop)])
        d = [f for f in res[2][1] if f.kind == "VPN_DISCONNECTED"][0]
        self.assertEqual(d.evidence["provider_state"], "connecting")
        self.assertEqual(d.summary, msg.VPN_RENEGOTIATING_BETWEEN_POLLS
                         % ("warp", msg.DUR_SECONDS % 2))
        p = [f for f in res[2][1] if f.kind == "VPN_PROTECTION_LOST"][0]
        self.assertTrue(p.summary.startswith(msg.VPN_PROTECTION_LOST_HEAD_RENEGOTIATING % "warp"))

    # QA-14 ───────────────────────────────────────────────────────────────
    def test_a_cause_line_is_attached_only_to_the_drop_that_follows_within_ten_seconds(self):
        cause = dl("05.000", "disconnect", "settings change")
        res = self.run_seq(self.start() + [self.o(10, [cause, dl("06.000", "status", "Connected")]),
                                           self.o(15, self.DROP[2:])])
        d = [f for f in res[3][1] if f.kind == "VPN_DISCONNECTED"][0]
        self.assertNotIn("settings change", [x["text"] for x in d.evidence["daemon_lines"]])
        old = dl("05.000", "disconnect", "settings change")
        late = [dl("16.000", "status", "Disconnected(SettingsChanged)"), dl("17.000", "status", "Connected")]
        res = self.run_seq(self.start() + [self.o(20, [old] + late)])
        d = [f for f in res[2][1] if f.kind == "VPN_DISCONNECTED"][0]
        self.assertIsNone(d.evidence["provider_reason"])


    def test_a_pending_cause_line_survives_a_window_and_a_restart(self):
        first = self.engine({})
        self.judge_seq(first, self.start() + [self.o(10, self.DROP[:2])])      # 원인 줄만 — 대기
        saved = json.loads(json.dumps(first.state))                              # state.json 을 거침
        second = self.engine(saved)                                               # 재시작
        out = self.judge_seq(second, [self.o(15, self.DROP[2:4], start=True), self.o(20, self.DROP[4:])])
        self.assertEqual([f.kind for f in out[0] if f.evidence.get("timing_source")], [])  # 재시작 첫 주기
        d = [f for f in out[1] if f.kind == "VPN_DISCONNECTED"][0]
        self.assertEqual([x["kind"] for x in d.evidence["daemon_lines"]],
                         ["error", "disconnect", "status", "status", "status"])

    def test_the_twenty_line_cap_keeps_the_causes_and_the_first_and_last_states(self):
        phases = [dl("08.%03d" % i, "status", "Connecting(Phase%d)" % (i % 2)) for i in range(40)]
        drop = self.DROP[:3] + phases + [dl("09.004", "status", "Connected")]
        res = self.run_seq(self.start() + [self.o(10, drop)])
        lines = [f for f in res[2][1] if f.kind == "VPN_DISCONNECTED"][0].evidence["daemon_lines"]
        self.assertEqual(len(lines), vpn_rules.DAEMON_OPEN_MAX)
        texts = [x["text"] for x in lines]
        self.assertEqual(texts[:3], [x["text"] for x in self.DROP[:3]])
        self.assertEqual(texts[-1], "Connected")

    def test_the_per_drop_cap_drops_middle_states_of_any_kind_oldest_first(self):
        """끊김당 20줄 상한(`_cap_open`): 첫·마지막 사이 상태 줄을 종류와 무관하게 오래된 것부터 버린다 — 보존본 01:56:12 긴 끊김에서
        `Disconnected(Manual)` 이 먼저 버려진 모양. 그래도 넘치면 원인 줄을 오래된 것부터 버리되 첫·마지막 상태 줄은 남긴다
        (DEV-7 (r2) 3회차 검수: 연결 단계 먼저·새 것부터 버리는 변이가 살아남았다, DEV-12 4회차 [범위 밖] C1~C3)."""
        first, last = dl("01.000", "status", "Unable(NoNetwork)"), dl("02.000", "status", "Connecting(Z)")
        mids = [dl("01.100", "status", "Disconnected(Manual)")] + [
            dl("01.%03d" % (200 + i), "status", "Connecting(P%d)" % (i % 2)) for i in range(19)]
        lines, dropped = vpn_rules._cap_open([first] + mids + [last], 0)            # 22줄
        self.assertEqual((len(lines), dropped), (20, 2))
        self.assertEqual([x["text"] for x in lines], [first["text"]] + [x["text"] for x in mids[2:]] + [last["text"]])
        s0, s1 = dl("03.000", "status", "Disconnected(X)"), dl("03.100", "status", "Connecting(Y)")
        causes = [dl("03.%03d" % (200 + i), "error", "e%d" % i) for i in range(20)]
        lines, dropped = vpn_rules._cap_open([s0, s1] + causes, 3)                    # 가운데 상태 줄 없음 — 22줄
        self.assertEqual((len(lines), dropped), (20, 5))
        self.assertEqual([x["text"] for x in lines], [s0["text"], s1["text"]] + ["e%d" % i for i in range(2, 20)])

    def test_a_state_or_line_time_with_a_trailing_newline_is_not_trusted(self):
        """DEV-13: 상태 파일의 데몬 상태 이름·줄 시각이 끝 개행을 달고 있으면 믿지 않는다(`$` 는 끝 개행 앞에서도 맞는다)."""
        st = vpn_rules._load_daemon_state({vpn_rules.DAEMON_STATE_KEY: {"state": "Connected\n", "pending": [],
                                                                       "open_since": None, "open_lines": [],
                                                                       "open_dropped": 0}})
        self.assertIsNone(st["state"])
        self.assertIsNone(vpn_rules._daemon_line({"ts": "2026-01-01T00:00:01.000Z\n", "kind": "status", "text": "x"}))
        self.assertIsNone(vpn_rules._daemon_time("2026-01-01T00:00:01.000Z\n"))
        # strptime 은 전각 숫자를 받는다 — 시각 모양은 ASCII 숫자로만(수집 쪽 정규식과 같게)
        self.assertIsNone(vpn_rules._daemon_time("\uff12\uff10\uff12\uff16-01-01T00:00:01.000Z"))

    def test_the_judge_side_rechecks_what_the_collector_would_have_stored(self):
        """DEV-14: 상태 파일·표본의 줄 글과 상태 이름을 수집 쪽 규칙으로 다시 본다 — 상태 줄·상태 이름은 이름 문법 왕복,
        원인 줄은 도려내기를 거친 글. 아니면 버린다(사람이 고친 파일의 날 개행·조작 문자·주소가 증거로 가지 않게)."""
        ts = "2026-01-01T00:00:01.000Z"
        for text in ("Connected\n", "Connected)", "A)((", "Connecting(k0123456789abcdef0123)", "Disconnected {x}"):
            self.assertIsNone(vpn_rules._daemon_line({"ts": ts, "kind": "status", "text": text}), text)
        for text in ("to 192.0.2.1 x", "a\nb", "a\u202eb", "key 0123456789abcdef0123"):
            self.assertIsNone(vpn_rules._daemon_line({"ts": ts, "kind": "error", "text": text}), text)
        self.assertEqual(vpn_rules._daemon_line({"ts": ts, "kind": "status", "text": "Unable(NoNetwork)"})["text"], "Unable(NoNetwork)")
        self.assertEqual(vpn_rules._daemon_line({"ts": ts, "kind": "disconnect", "text": "to <addr> x"})["text"], "to <addr> x")
        for name in ("Connected)", "A)((", "Connected {x}"):
            st = vpn_rules._load_daemon_state({vpn_rules.DAEMON_STATE_KEY: {"state": name, "pending": [], "open_since": None,
                                                                           "open_lines": [], "open_dropped": 0}})
            self.assertIsNone(st["state"], name)
        st = vpn_rules._load_daemon_state({vpn_rules.DAEMON_STATE_KEY: {"state": "Unable(NoNetwork)", "pending": [],
                                                                       "open_since": None, "open_lines": [], "open_dropped": 0}})
        self.assertEqual(st["state"], "Unable(NoNetwork)")

    def test_a_tampered_sample_line_does_not_reach_the_evidence(self):
        bad = [dl("07.490", "error", "to 192.0.2.1 x"), dl("07.491", "disconnect", "a\nb")]
        res = self.run_seq(self.start() + [self.o(10, bad + self.DROP[2:])])
        d = [f for f in res[2][1] if f.kind == "VPN_DISCONNECTED"][0]
        self.assertNotIn("192.0.2.1", json.dumps(d.evidence))
        self.assertEqual([x["kind"] for x in d.evidence["daemon_lines"]], ["status", "status", "status"])

    def test_every_path_that_reads_stored_lines_rechecks_them(self):
        """재검사(`_daemon_line`)를 부르는 세 경로 — 상태 파일의 줄 목록(`_daemon_lines`), 넘어온 창(`_carry_items`), 링크 없는
        주기의 표본 줄(`daemon_evidence_without_link`) — 가 각자 조작된 줄을 버린다(FINAL 1회차 [낮음]: 한 경로에서만 재검사를
        뺀 변이 셋이 전체 시험을 통과했다)."""
        good = dl("07.493", "status", "Disconnected(InternalTunnelError)")
        bad = [dl("07.490", "error", "to 192.0.2.1 x"), dl("07.491", "status", "Connected\n")]
        self.assertEqual(vpn_rules._daemon_lines(bad + [good], 10), [good])
        self.assertEqual(vpn_rules._carry_items(bad + [{"kind": "reset"}, good]), [{"kind": "reset"}, good])
        state = {vpn_rules.DAEMON_STATE_KEY: {"state": "Connected", "pending": [], "open_since": None,
                                              "open_lines": [], "open_dropped": 0}}
        ev = vpn_rules.daemon_evidence_without_link(state, self.o(10, bad + [good], state="disconnected", link=False))
        self.assertNotIn("192.0.2.1", json.dumps(ev))
        self.assertEqual(ev["daemon_lines"], [good])

    # ADV-6 (판정 쪽 키) ─────────────────────────────────────────────────────
    def test_broken_state_keys_restart_from_unknown_without_an_exception(self):
        broken = [{"warp_daemon_state": "x"}, {"warp_daemon_state": {"state": 5, "pending": "x"}},
                  {"warp_daemon_state": {"state": "Connected", "pending": [{"ts": 1}] * 10 ** 5}},
                  {"warp_daemon_carry": [{"ts": "x"}] * 10 ** 5, "warp_daemon_carry_gap": "yes"},
                  {"warp_daemon_polls": "connected"}, {"warp_daemon_polls": [None] * 10 ** 5},
                  {"warp_daemon_state": {"state": "Disconnected(X)", "open_since": "yesterday",
                                         "open_lines": [None, 3, {"ts": "2026-01-01T00:00:01.000Z",
                                                                  "kind": "evil", "text": "x"}],
                                         "open_dropped": -4}}]
        for bad in broken:
            eng = self.engine(dict(bad))
            eng.judge(self.o(10, self.DROP), 5.0)
            st = eng.state.get(vpn_rules.DAEMON_STATE_KEY)
            self.assertIsInstance(st, dict, bad)
            self.assertLessEqual(len(st["pending"]), vpn_rules.DAEMON_PENDING_MAX)
            self.assertLessEqual(len(st["open_lines"]), vpn_rules.DAEMON_OPEN_MAX)
            json.dumps(eng.state)

    def test_the_carried_window_is_capped_and_forgets_the_state_when_it_overflows(self):
        many = [dl("%02d.%03d" % (i // 1000, i % 1000), "status", "Connecting(P%d)" % (i % 2))
                for i in range(vpn_rules.DAEMON_CARRY_MAX + 10)]
        state = {}
        vpn_rules.carry_warp_daemon(state, self.o(10, many, link=False), gap=False)
        carry = state[vpn_rules.DAEMON_CARRY_KEY]
        self.assertEqual(len(carry), vpn_rules.DAEMON_CARRY_MAX)
        self.assertEqual(carry[0], {"kind": "reset"})          # 버린 사이의 전환을 모름 — 판정 주기에 "모름" 으로
        state[vpn_rules.DAEMON_STATE_KEY] = {"state": "Connected", "pending": [], "open_since": None,
                                             "open_lines": [], "open_dropped": 0}
        vpn_rules.warp_daemon_window(state, self.o(15), suppress=False)
        self.assertEqual(state[vpn_rules.DAEMON_STATE_KEY]["state"], "Connecting(P1)")
        self.assertIsNone(state[vpn_rules.DAEMON_STATE_KEY]["open_since"])   # 시작을 모르는 끊김

    # ADV-7 ───────────────────────────────────────────────────────────────
    def test_a_clock_going_backwards_never_gives_a_negative_duration(self):
        drop = [dl("09.000", "status", "Disconnected(InternalTunnelError)"), dl("07.000", "status", "Connected")]
        res = self.run_seq(self.start() + [self.o(10, drop)])
        r = [f for f in res[2][1] if f.kind == "VPN_RECONNECTED"][0]
        self.assertIsNone(r.evidence["down_seconds"])                  # 음수도 0 도 아닌 "모름"(DEV-4 3회차)
        cause_after = [dl("09.500", "disconnect", "settings change"),
                       dl("09.000", "status", "Disconnected(SettingsChanged)"), dl("09.600", "status", "Connected")]
        res = self.run_seq(self.start() + [self.o(10, cause_after)])
        d = [f for f in res[2][1] if f.kind == "VPN_DISCONNECTED"][0]
        self.assertEqual(d.evidence["provider_reason"], "settings change")

    DROP2 = [dl("21.490", "error", "TunnelError(SocketRecv(BrokenPipe))"),
             dl("21.493", "status", "Disconnected(InternalTunnelError)"),
             dl("23.004", "status", "Connected")]

    def test_the_first_judged_cycle_after_a_restart_gives_nothing_even_with_a_saved_state(self):
        """K-8: 저장된 상태(직전 조회 connected, 데몬 Connected)로 재시작해도 첫 판정 주기의 끊김은 새 판정이 없다."""
        first = self.engine({})
        self.judge_seq(first, self.start())
        saved = json.loads(json.dumps(first.state))
        second = self.engine(saved)
        out = self.judge_seq(second, [self.o(10, self.DROP, start=True), self.o(25, self.DROP2)])
        self.assertEqual([f.kind for f in out[0] if f.evidence.get("timing_source")], [])
        self.assertEqual([f.kind for f in out[1] if f.evidence.get("timing_source")],
                         ["VPN_DISCONNECTED", "VPN_PROTECTION_LOST", "VPN_RECONNECTED"])

    def test_a_carried_drop_is_judged_exactly_once(self):
        res = self.run_seq(self.start() + [self.o(10, self.DROP, link=False), self.o(15), self.o(20), self.o(25)])
        self.assertEqual([len(self.daemon_kinds(res, i)) for i in range(len(res))], [0, 0, 0, 2, 0, 0])

    def test_a_short_drop_after_a_poll_caught_drop_is_judged(self):
        res = self.run_seq(self.start() + [self.o(10, self.DROP[:3], state="disconnected"),
                                           self.o(15, self.DROP[3:]), self.o(20), self.o(25, self.DROP2)])
        self.assertEqual(self.daemon_kinds(res, 5), ["VPN_DISCONNECTED", "VPN_PROTECTION_LOST", "VPN_RECONNECTED"])

    def test_a_short_drop_after_a_carried_gap_is_judged_later(self):
        res = self.run_seq(self.start() + [self.o(100, link=False), self.o(105), self.o(110, self.DROP2)])
        self.assertEqual(self.daemon_kinds(res, 3), [])
        self.assertEqual(self.daemon_kinds(res, 4), ["VPN_DISCONNECTED", "VPN_PROTECTION_LOST", "VPN_RECONNECTED"])

    def test_a_reset_in_a_cycle_without_a_link_does_not_join_lines_across_it(self):
        res = self.run_seq(self.start() + [self.o(10, self.DROP[:3], link=False),
                                           self.o(15, self.DROP[3:], link=False, reset=True), self.o(20)])
        self.assertEqual([k for i in range(len(res)) for k in self.daemon_kinds(res, i)], [])

    def test_a_drop_closed_before_a_reset_in_a_cycle_without_a_link_is_still_judged(self):
        res = self.run_seq(self.start() + [self.o(10, self.DROP, link=False),
                                           self.o(15, link=False, reset=True), self.o(20)])
        self.assertEqual(self.daemon_kinds(res, 4), ["VPN_DISCONNECTED", "VPN_RECONNECTED"])

    def test_an_overflowing_poll_list_does_not_forget_a_disconnected_poll(self):
        """조회 목록이 상한을 넘어도 직전 판정 주기의 비연결 조회를 잊지 않는다(넘치면 조건 불충족)."""
        seq = self.start() + [self.o(10, self.DROP[:3], state="disconnected"),
                              self.o(15, self.DROP[3:], link=False)]
        seq += [self.o(20 + 5 * i, link=False) for i in range(vpn_rules.DAEMON_POLLS_MAX)]
        seq += [self.o(20 + 5 * vpn_rules.DAEMON_POLLS_MAX)]
        res = self.run_seq(seq)
        self.assertEqual([k for i in range(len(res)) for k in self.daemon_kinds(res, i)], [])

    def test_huge_broken_states_are_capped_in_an_eligible_window(self):
        """ADV-6: 판정 조건을 채운 창에서, 모양이 맞는 거대한 대기·열린 줄이 와도 상한·시간을 지키고 오류가 없다."""
        import time
        line = dl("05.000", "disconnect", "x")
        cases = [("Connected", "pending", self.DROP[2:3]),                       # 대기 줄이 전부 원인으로 붙는 순간
                 ("Disconnected(X)", "open_lines", self.DROP[3:4])]               # 열린 끊김에 줄이 더해지는 순간
        for state_name, key, window in cases:
            st = {"state": state_name, "pending": [], "open_since": "2026-01-01T00:00:04.000Z",
                  "open_lines": [], "open_dropped": 0}
            st[key] = [dict(line)] * 20000
            eng = self.engine(json.loads(json.dumps({"warp_daemon_state": st, "warp_daemon_polls": ["connected"]})))
            eng.prev = self.o(5)
            start = time.time()
            out = eng.judge(self.o(10, window), 5.0)          # 끊김이 열린 채로 끝남
            self.assertLess(time.time() - start, 1.0, key)
            st = eng.state[vpn_rules.DAEMON_STATE_KEY]
            self.assertLessEqual(len(st["pending"]), vpn_rules.DAEMON_PENDING_MAX, key)
            self.assertLessEqual(len(st["open_lines"]), vpn_rules.DAEMON_OPEN_MAX, key)
            self.assertEqual([f for f in out if f.kind == "DETECTOR_ERROR"], [], key)

    # QA-10 ───────────────────────────────────────────────────────────────
    def test_the_same_samples_give_the_same_findings_after_a_round_trip(self):
        from netmon.model import Observation
        seq = self.start() + [self.o(10, self.DROP[:3]), self.o(15, self.DROP[3:]),
                              self.o(20, self.DROP, reset=True), self.o(25, self.DROP)]
        again = [Observation(ts=o.ts, data=json.loads(json.dumps(o.data))) for o in seq]
        a = [(f.kind, f.evidence) for _, fs in self.run_seq(seq) for f in fs]
        b = [(f.kind, f.evidence) for _, fs in self.run_seq(again) for f in fs]
        self.assertEqual(a, b)
        self.assertIn("VPN_DISCONNECTED", [k for k, _ in a])

    def test_a_bug_in_the_daemon_path_keeps_the_poll_findings_of_the_same_cycle(self):
        with mock.patch.object(vpn_rules, "daemon_findings", side_effect=ValueError("boom")):
            res = enginemod_replay(self.cfg, self.start() + [self.o(10, state="disconnected")])
        kinds = [f.kind for f in res[2][1]]
        self.assertIn("VPN_DISCONNECTED", kinds)
        self.assertIn("DETECTOR_ERROR", kinds)
        err = [f for f in res[2][1] if f.kind == "DETECTOR_ERROR"][0]
        self.assertEqual(err.evidence["detector"], "detect.vpn.daemon")
        self.assertIn("detect.vpn.daemon", err.summary)

    def test_no_daemon_data_means_nothing_new_and_no_state(self):
        seq = self.start() + [self.o(10, self.DROP)]
        eng = self.engine({})
        self.judge_seq(eng, seq[:2])
        self.assertTrue([k for k in eng.state if k.startswith("warp_daemon")])
        for o in seq:
            del o.data["warp_daemon"]
        res = self.run_seq(seq)
        self.assertEqual([k for i in range(len(res)) for k in self.daemon_kinds(res, i)], [])
        self.judge_seq(eng, seq[2:])
        self.assertEqual([k for k in eng.state if k.startswith("warp_daemon")], [])


    # DEV-4 3회차 ────────────────────────────────────────────────────────────
    def test_a_clock_going_backwards_leaves_the_length_unknown(self):
        """복귀 시각이 이탈 시각보다 이르면 길이를 적지 않는다(조회 경로 `_elapsed_seconds` 와 같음)."""
        drop = [dl("09.000", "status", "Disconnected(InternalTunnelError)"), dl("08.000", "status", "Connected")]
        res = self.run_seq(self.start() + [self.o(10, drop)])
        d = [f for f in res[2][1] if f.kind == "VPN_DISCONNECTED"][0]
        r = [f for f in res[2][1] if f.kind == "VPN_RECONNECTED"][0]
        self.assertIsNone(r.evidence["down_seconds"])
        self.assertNotIn(msg.DUR_UNDER_SECOND, d.summary)
        self.assertIn(msg.DUR_UNKNOWN, d.summary)

    def test_one_window_judges_at_most_ten_drops_and_counts_the_rest(self):
        drops = []
        for i in range(15):
            drops += [dl("05.%03d" % (i * 20), "status", "Disconnected(X)"),
                      dl("05.%03d" % (i * 20 + 10), "status", "Connected")]
        res = self.run_seq(self.start() + [self.o(10, drops)])
        kinds = self.daemon_kinds(res, 2)
        self.assertEqual(kinds, ["VPN_DISCONNECTED", "VPN_PROTECTION_LOST", "VPN_RECONNECTED"] * vpn_rules.DAEMON_DROPS_MAX)
        last = [f for f in res[2][1] if f.kind == "VPN_RECONNECTED"][-1]
        self.assertEqual(last.evidence["daemon_drops_not_judged"], 15 - vpn_rules.DAEMON_DROPS_MAX)
        first = [f for f in res[2][1] if f.kind == "VPN_RECONNECTED"][0]
        self.assertNotIn("daemon_drops_not_judged", first.evidence)
        few = self.run_seq(self.start() + [self.o(10, self.DROP)])
        self.assertNotIn("daemon_drops_not_judged", [f for f in few[2][1] if f.kind == "VPN_RECONNECTED"][0].evidence)

    def test_a_drop_that_started_without_a_link_gets_no_protection_lost(self):
        """링크 없는 주기에 읽은 줄에서 시작한 끊김은 끊김·복구만(조회 경로도 링크 없는 주기엔 보호 상실을 내지 않음)."""
        res = self.run_seq(self.start() + [self.o(10, self.DROP, link=False), self.o(15)])
        self.assertEqual(self.daemon_kinds(res, 3), ["VPN_DISCONNECTED", "VPN_RECONNECTED"])
        res = self.run_seq(self.start() + [self.o(10, self.DROP[:3], link=False), self.o(15, self.DROP[3:])])
        self.assertEqual(self.daemon_kinds(res, 3), ["VPN_DISCONNECTED", "VPN_RECONNECTED"])
        res = self.run_seq(self.start() + [self.o(10, link=False), self.o(15, self.DROP2)])
        self.assertEqual(self.daemon_kinds(res, 3), ["VPN_DISCONNECTED", "VPN_PROTECTION_LOST", "VPN_RECONNECTED"])
        # 링크가 있을 때 시작해 링크 없는 주기에 닫힌 끊김은 링크 없는 주기에 시작한 것이 아니다
        res = self.run_seq(self.start() + [self.o(10, self.DROP[:3]), self.o(15, self.DROP[3:], link=False), self.o(20)])
        self.assertEqual(self.daemon_kinds(res, 4), ["VPN_DISCONNECTED", "VPN_PROTECTION_LOST", "VPN_RECONNECTED"])

    def test_a_restart_in_a_cycle_without_a_link_holds_back_the_next_judged_window(self):
        """첫 읽기가 링크 없는 주기면 다음 판정 주기의 창도 새 판정이 없다(K-8 — `warp_daemon_carry_gap` 과 같이)."""
        res = self.run_seq(self.start() + [self.o(10, link=False, start=True), self.o(15, self.DROP),
                                           self.o(20), self.o(25, self.DROP2)])
        self.assertEqual(self.daemon_kinds(res, 3), [])
        self.assertEqual(self.daemon_kinds(res, 5), ["VPN_DISCONNECTED", "VPN_PROTECTION_LOST", "VPN_RECONNECTED"])

    def test_one_known_poll_is_not_enough(self):
        """조건은 직전 판정 주기의 조회와 그 뒤의 조회 — 직전 판정 주기의 조회를 모르면(목록에 이번 것 하나) 판정하지 않는다."""
        state = {vpn_rules.DAEMON_STATE_KEY: {"state": "Connected", "pending": [], "open_since": None,
                                             "open_lines": [], "open_dropped": 0}}
        w = vpn_rules.warp_daemon_window(state, self.o(10, self.DROP), suppress=False)
        self.assertFalse(w["eligible"])
        self.assertEqual(len(w["closed"]), 1)

    def test_a_cause_line_far_after_the_drop_on_a_backward_clock_is_not_attached(self):
        late = dl("25.000", "disconnect", "settings change")        # 끊김 방송보다 17.5초 뒤 시각
        res = self.run_seq(self.start() + [self.o(10, [late] + self.DROP[2:])])
        d = [f for f in res[2][1] if f.kind == "VPN_DISCONNECTED"][0]
        self.assertIsNone(d.evidence["provider_reason"])

    def test_many_cause_lines_in_one_window_keep_the_pending_cap(self):
        many = [dl("05.%03d" % i, "error", "x%d" % i) for i in range(3 * vpn_rules.DAEMON_PENDING_MAX)]
        state = {}
        vpn_rules.warp_daemon_window(state, self.o(0, [dl("00.000", "status", "Connected")] + many), suppress=False)
        pending = state[vpn_rules.DAEMON_STATE_KEY]["pending"]
        self.assertEqual(len(pending), vpn_rules.DAEMON_PENDING_MAX)
        self.assertEqual(pending[-1]["text"], many[-1]["text"])

    # 실제 수집 경로와 replay (DEV-4 2회차 검수 [중간] 두 건 — QA-10, QA-14, TODO K-1 수집 쪽 보류, K-8) ──
    def live(self, eng, sec, raw, **kw):
        """원문 줄을 실제 수집 경로(`_read_warp_daemon` → `parse_warp_daemon`)로 표본에 싣고 판정한다."""
        def read(pos, *a, **k):
            last = pos.get("last_status") if isinstance(pos, dict) else None
            return list(raw), {"file": "1:1", "offset": 100 + sec, "last_status": last}, \
                {"read": "ok", "skipped_bytes": 0, "reset": False}
        with mock.patch.object(vpnmod, "read_warp_daemon", side_effect=read):
            wd = eng._read_warp_daemon()
        ob = self.o(sec, **kw)
        ob.data["warp_daemon"] = wd
        found = eng.judge(ob, 5.0)
        eng.prev = ob
        return ob, found

    def at(self, s):
        return "2026-01-01T00:00:%sZ" % s

    def live_and_replay(self, cycles, restart_before=None):
        eng = self.engine({})
        seq, live = [], []
        for i, (sec, raw) in enumerate(cycles):
            if i == restart_before:
                eng = self.engine(json.loads(json.dumps(eng.state)))
            ob, found = self.live(eng, sec, raw)
            seq.append(ob)
            live.append(found)
        replayed = [fs for _, fs in self.run_seq(seq)]
        key = lambda fss: [[(f.kind, f.evidence.get("provider_reason")) for f in fs
                            if f.evidence.get("timing_source") == "daemon"] for fs in fss]
        self.assertEqual(key(live), key(replayed))
        return live

    def test_a_cause_line_answered_by_a_repeated_connected_is_dropped_on_the_real_path(self):
        base = [(0, [daemon_status("Connected", ts=self.at("00.000"))]), (5, [])]
        tail = [(15, [daemon_status("Disconnected(InternalTunnelError)", ts=self.at("12.000")),
                      daemon_status("Connected", ts=self.at("12.800"))])]
        same_read = [(10, [daemon_disconnect("settings change", ts=self.at("07.000")),
                           daemon_status("Connected", ts=self.at("07.001"))])]
        across = [(10, [daemon_disconnect("settings change", ts=self.at("07.000"))])]
        across_tail = [(15, [daemon_status("Connected", ts=self.at("07.001"))] + tail[0][1])]
        for cycles in (base + same_read + tail, base + across + across_tail):
            live = self.live_and_replay(cycles)
            d = [f for f in live[3] if f.kind == "VPN_DISCONNECTED"][0]
            self.assertIsNone(d.evidence["provider_reason"])
            self.assertNotIn("settings change", [x["text"] for x in d.evidence["daemon_lines"]])

    def test_a_cause_line_followed_by_its_drop_is_kept_on_the_real_path(self):
        cycles = [(0, [daemon_status("Connected", ts=self.at("00.000"))]), (5, []),
                  (10, [daemon_disconnect("settings change", ts=self.at("09.990"))]),
                  (15, [daemon_status("Disconnected(SettingsChanged)", ts=self.at("09.995")),
                        daemon_status("Connected", ts=self.at("12.800"))])]
        live = self.live_and_replay(cycles)
        d = [f for f in live[3] if f.kind == "VPN_DISCONNECTED"][0]
        self.assertEqual(d.evidence["provider_reason"], "settings change")

    def test_a_short_restart_gives_the_same_findings_live_and_in_replay(self):
        """재시작 뒤 첫 판정 주기의 억제가 표본에 남아 replay 도 같은 결과를 낸다(메모리 표지면 갈렸다)."""
        drop = [daemon_status("Disconnected(InternalTunnelError)", ts=self.at("12.000")),
                daemon_status("Connecting(CheckingNetwork)", ts=self.at("12.500")),
                daemon_status("Connected", ts=self.at("13.000"))]
        cycles = [(0, [daemon_status("Connected", ts=self.at("00.000"))]), (5, []), (10, []),
                  (15, drop), (20, []), (25, [])]
        live = self.live_and_replay(cycles, restart_before=3)
        self.assertEqual([f.kind for f in live[3] if f.evidence.get("timing_source") == "daemon"], [])


class TestDaemonEvidenceOnPollFindings(_DaemonSequence, unittest.TestCase):
    """조회 경로의 WARP 끊김·복구 판정에도 데몬 로그 줄을 붙이고, 새 경로 요약문은 고정 목록만 인용한다
    (DEV-5 — QA-7, QA-9)."""

    def poll(self, res, i, kind):
        return [f for f in res[i][1] if f.kind == kind and f.evidence.get("timing_source") != "daemon"]

    # QA-7 ────────────────────────────────────────────────────────────────
    def test_a_poll_drop_gets_the_open_drop_lines(self):
        res = self.run_seq(self.start() + [self.o(10, self.DROP[:3], state="disconnected")])
        d = self.poll(res, 2, "VPN_DISCONNECTED")[0]
        self.assertEqual(d.evidence["daemon_read"], "ok")
        self.assertEqual([x["text"] for x in d.evidence["daemon_lines"]], [x["text"] for x in self.DROP[:3]])

    def test_a_poll_drop_that_already_closed_in_the_window_gets_those_lines(self):
        res = self.run_seq(self.start() + [self.o(10, self.DROP, state="disconnected")])
        d = self.poll(res, 2, "VPN_DISCONNECTED")[0]
        self.assertEqual(len(d.evidence["daemon_lines"]), len(self.DROP))
        self.assertEqual(self.daemon_kinds(res, 2), [])

    def test_the_recovery_gets_every_line_of_the_drop_even_a_later_cause(self):
        """조회로 잡힌 끊김의 끊김 판정은 뒤에 찍힌 분류를 담을 수 없다 — 복구 판정이 담는다(K-6)."""
        later = dl("11.000", "disconnect", "settings change")
        res = self.run_seq(self.start() + [self.o(10, self.DROP[:3], state="disconnected"),
                                           self.o(15, [later], state="disconnected"),
                                           self.o(20, self.DROP[3:])])
        r = self.poll(res, 4, "VPN_RECONNECTED")[0]
        texts = [x["text"] for x in r.evidence["daemon_lines"]]
        self.assertIn("runtime connection failure failure=Tunnel", texts)
        self.assertIn("settings change", texts)
        self.assertEqual(texts[-1], "Connected")

    def test_a_recovery_one_window_late_still_gets_the_lines(self):
        """데몬은 이미 돌아왔는데(이번 창) 조회는 다음 주기에 연결을 본다 — 직전 창의 닫힌 끊김을 쓴다."""
        res = self.run_seq(self.start() + [self.o(10, self.DROP, state="disconnected"), self.o(15)])
        r = self.poll(res, 3, "VPN_RECONNECTED")[0]
        self.assertEqual(len(r.evidence["daemon_lines"]), len(self.DROP))

    def test_a_drop_in_a_cycle_without_a_link_gets_daemon_evidence(self):
        from netmon.detect import vpn as rules
        cur = self.o(10, self.DROP[:3], state="disconnected", link=False)
        found, _ = rules.without_link(vpn_state("connected"), cur, {})
        d = [f for f in found if f.kind == "VPN_DISCONNECTED"][0]
        self.assertEqual(d.evidence["daemon_read"], "ok")
        self.assertEqual([x["text"] for x in d.evidence["daemon_lines"]], [x["text"] for x in self.DROP[:3]])

    def test_the_evidence_of_a_cycle_without_a_link_does_not_change_the_state(self):
        from netmon.detect import vpn as rules
        state = {"warp_daemon_carry": [dict(x) for x in self.DROP[:2]]}
        before = json.dumps(state, sort_keys=True)
        rules.daemon_evidence_without_link(state, self.o(10, self.DROP[2:3], link=False))
        self.assertEqual(json.dumps(state, sort_keys=True), before)

    def test_a_recovery_after_a_cycle_without_a_link_gets_only_its_own_drop(self):
        """링크 없는 사이의 복구 판정에 이미 복구된 다른 끊김의 줄이 붙지 않는다(K-6 "그 끊김의 줄")."""
        drop_b = [dl("21.493", "status", "Disconnected(InternalTunnelError)")]
        res = self.run_seq(self.start() + [self.o(10, self.DROP[:3], state="disconnected"),     # 끊김 A (조회로 잡힘)
                                           self.o(15, self.DROP[3:]),                            # A 복구
                                           self.o(20, drop_b, state="disconnected", link=False),  # 끊김 B (링크 없음)
                                           self.o(25, [dl("23.004", "status", "Connected")])])   # B 복구
        r = [f for f in res[5][1] if f.kind == "VPN_RECONNECTED"][0]
        texts = [x["text"] for x in r.evidence["daemon_lines"]]
        self.assertNotIn("runtime connection failure failure=Tunnel", texts)      # A 의 분류 줄
        self.assertEqual(texts, ["Disconnected(InternalTunnelError)", "Connected"])

    def test_the_evidence_of_a_cycle_without_a_link_uses_the_carried_lines_once(self):
        from netmon.detect import vpn as rules
        state = {"warp_daemon_carry": [dict(x) for x in self.DROP[:2]]}
        ev = rules.daemon_evidence_without_link(state, self.o(10, self.DROP[2:3], link=False))
        self.assertEqual([x["text"] for x in ev["daemon_lines"]], [x["text"] for x in self.DROP[:3]])
        # 엔진에서도 줄이 두 번 붙지 않는다(넘기기는 증거 계산 뒤)
        res = self.run_seq(self.start() + [self.o(10, self.DROP[:3], state="disconnected", link=False)])
        d = [f for f in res[2][1] if f.kind == "VPN_DISCONNECTED"][0]
        self.assertEqual(len(d.evidence["daemon_lines"]), 3)

    def test_the_evidence_of_a_cycle_without_a_link_respects_a_reset(self):
        from netmon.detect import vpn as rules
        state = {"warp_daemon_carry": [dict(self.DROP[2])]}
        ev = rules.daemon_evidence_without_link(state, self.o(10, self.DROP[4:], link=False, reset=True))
        self.assertEqual(ev["daemon_lines"], [])       # reset 너머의 Connected 는 앞의 끊김을 닫지 않는다

    def test_no_daemon_data_is_absent_and_no_lines_is_an_empty_list(self):
        seq = self.start() + [self.o(10, state="disconnected")]
        del seq[2].data["warp_daemon"]
        d = self.poll(self.run_seq(seq), 2, "VPN_DISCONNECTED")[0]
        self.assertEqual((d.evidence["daemon_read"], d.evidence["daemon_lines"]), ("absent", []))
        d = self.poll(self.run_seq(self.start() + [self.o(10, state="disconnected")]), 2, "VPN_DISCONNECTED")[0]
        self.assertEqual((d.evidence["daemon_read"], d.evidence["daemon_lines"]), ("ok", []))

    def test_a_read_failure_is_named_on_the_finding(self):
        d = self.poll(self.run_seq(self.start() + [self.o(10, state="disconnected", read="unreadable")]),
                      2, "VPN_DISCONNECTED")[0]
        self.assertEqual((d.evidence["daemon_read"], d.evidence["daemon_lines"]), ("unreadable", []))

    def test_other_providers_get_no_daemon_keys(self):
        prev = obs(ts="2026-01-01T00:00:05Z", vpn=vpn_state("connected", provider="tailscale"), security="WPA2_PSK")
        cur = obs(ts="2026-01-01T00:00:10Z", vpn=vpn_state("disconnected", provider="tailscale"), security="WPA2_PSK")
        d = [f for f in judge(prev, cur) if f.kind == "VPN_DISCONNECTED"][0]
        self.assertNotIn("daemon_read", d.evidence)
        self.assertNotIn("daemon_lines", d.evidence)

    # QA-9 ────────────────────────────────────────────────────────────────
    def test_only_the_fixed_list_is_quoted_by_its_outer_reason_name(self):
        cases = [("Disconnected(InternalTunnelError)", "InternalTunnelError"),
                 ("Unable(ConnectivityCheckFailed(Unknown))", "ConnectivityCheckFailed"),
                 ("Disconnected(SettingsChanged)", "SettingsChanged"),
                 ("Unable(NoNetwork)", "NoNetwork"),
                 ("Disconnected(Manual)", None),
                 ("Disconnected(InternalTunnelErrorX)", None),
                 ("Disconnected(Settings)", None),
                 ("Unable(NoNetworkAtAll)", None),
                 ("Disconnected(SomethingNew)", None),
                 ("Disconnected", None),
                 ("Connecting(PerformingHappyEyeballs)", None)]
        for state_name, quoted in cases:
            drop = [dl("07.493", "status", state_name), dl("09.004", "status", "Connected")]
            d = [f for f in self.run_seq(self.start() + [self.o(10, drop)])[2][1]
                 if f.kind == "VPN_DISCONNECTED"][0]
            tail = " " + msg.VPN_DAEMON_REASON % quoted if quoted else ""
            self.assertTrue(d.summary.endswith(("원인을 좁히지 않음." if msg.VPN_DAEMON_REASON.startswith("데몬")
                                                else "narrowed down.") + tail), (state_name, d.summary))
            for part in ("Manual", "SomethingNew", "PerformingHappyEyeballs", "ErrorX", "Settings)", "AtAll"):
                self.assertNotIn(part, d.summary, state_name)

    def test_the_poll_summaries_are_unchanged(self):
        res = self.run_seq(self.start() + [self.o(10, self.DROP[:3], state="disconnected")])
        d = self.poll(res, 2, "VPN_DISCONNECTED")[0]
        self.assertNotIn(msg.VPN_DAEMON_REASON.split("%")[0].strip(), d.summary)


    # DEV-11 (DEV-5 2회차 검수 [낮음]) ──────────────────────────────────────
    def test_the_names_read_from_the_binary_are_quoted_too(self):
        """고정 목록 가운데 바이너리에서 끊어 읽은 세 이름도 인용한다(보존본에서 본 넷은 위 시험이 본다)."""
        for state_name, quoted in (("Disconnected(ProxyAddressBound)", "ProxyAddressBound"),
                                   ("Unable(TLSInterceptionBlockingDOH)", "TLSInterceptionBlockingDOH"),
                                   ("Unable(Port53Bound)", "Port53Bound")):
            drop = [dl("07.493", "status", state_name), dl("09.004", "status", "Connected")]
            d = [f for f in self.run_seq(self.start() + [self.o(10, drop)])[2][1] if f.kind == "VPN_DISCONNECTED"][0]
            self.assertTrue(d.summary.endswith(" " + msg.VPN_DAEMON_REASON % quoted), (state_name, d.summary))

    def test_a_recovery_does_not_get_the_lines_of_a_drop_that_just_opened(self):
        """복구 증거("up")는 닫힌 끊김의 줄만 — 조회가 연결을 본 뒤 새로 열린 끊김의 줄은 붙지 않는다."""
        opened = dl("13.000", "status", "Disconnected(NoNetwork)")
        res = self.run_seq(self.start() + [self.o(10, self.DROP[:3], state="disconnected"),
                                           self.o(15, self.DROP[3:] + [opened])])
        r = self.poll(res, 3, "VPN_RECONNECTED")[0]
        texts = [x["text"] for x in r.evidence["daemon_lines"]]
        self.assertIn("Disconnected(InternalTunnelError)", texts)
        self.assertNotIn("Disconnected(NoNetwork)", texts)

    def test_a_recovery_across_a_cycle_without_a_link_uses_the_recovery_evidence(self):
        """링크 없는 사이의 복구 판정도 "up" 증거 — 같은 창에서 새로 열린 끊김의 줄은 붙지 않는다."""
        drop_b = [dl("21.493", "status", "Disconnected(InternalTunnelError)")]
        opened = dl("24.000", "status", "Disconnected(NoNetwork)")
        res = self.run_seq(self.start() + [self.o(10), self.o(15),
                                           self.o(20, drop_b, state="disconnected", link=False),
                                           self.o(25, [dl("23.004", "status", "Connected"), opened])])
        r = [f for f in res[5][1] if f.kind == "VPN_RECONNECTED" and f.evidence.get("link_absent")][0]
        texts = [x["text"] for x in r.evidence["daemon_lines"]]
        self.assertEqual(texts, ["Disconnected(InternalTunnelError)", "Connected"])

    def test_a_broken_previous_closed_key_never_costs_a_poll_recovery(self):
        """깨진 `warp_daemon_prev_closed` 가 조회 경로 복구 판정의 증거 계산에서 예외를 내지 않는다(ADV-6)."""
        for bad in ([5], "abc", 5, {"x": 1}, [None, [1, 2], {"ts": "x"}],
                    [{"ts": "2026-01-01T00:00:01.000Z", "kind": "status", "text": "x" * 10 ** 6}]):
            eng = self.engine({})
            self.judge_seq(eng, self.start() + [self.o(10, self.DROP[:3], state="disconnected")])
            eng.state[vpn_rules.DAEMON_PREV_CLOSED_KEY] = bad
            out = eng.judge(self.o(15, self.DROP[3:]), 5.0)
            self.assertEqual([f for f in out if f.kind == "DETECTOR_ERROR"], [], repr(bad)[:40])
            r = [f for f in out if f.kind == "VPN_RECONNECTED"]
            self.assertEqual(len(r), 1, repr(bad)[:40])
            # 깨진 항목은 버리고 이 끊김의 다섯 줄만(DEV-14 — 단언 강화)
            self.assertEqual([x["text"] for x in r[0].evidence["daemon_lines"]], [x["text"] for x in self.DROP], repr(bad)[:40])


    # DEV-12 잘림 표시와 조회 경로 상한 ────────────────────────────────────────
    def many_drops(self, n, start=5):
        out = []
        for i in range(n):
            out += [dl("%02d.%03d" % (start, i * 20), "status", "Disconnected(X)"),
                    dl("%02d.%03d" % (start, i * 20 + 10), "status", "Connected")]
        return out

    def test_a_poll_finding_keeps_the_last_lines_and_counts_the_rest(self):
        drops = self.many_drops(30)                                            # 닫힌 끊김 30건 = 60줄
        res = self.run_seq(self.start() + [self.o(10, drops + self.DROP[:3], state="disconnected")])
        d = self.poll(res, 2, "VPN_DISCONNECTED")[0]
        self.assertEqual(len(d.evidence["daemon_lines"]), vpn_rules.DAEMON_EVIDENCE_MAX)
        self.assertEqual(d.evidence["daemon_lines_dropped"], 63 - vpn_rules.DAEMON_EVIDENCE_MAX)
        self.assertEqual(d.evidence["daemon_lines"][-1]["text"], "Disconnected(InternalTunnelError)")   # 열린 끊김이 남는다
        small = self.poll(self.run_seq(self.start() + [self.o(10, self.DROP[:3], state="disconnected")]), 2,
                          "VPN_DISCONNECTED")[0]
        self.assertNotIn("daemon_lines_dropped", small.evidence)

    def test_a_long_drop_counts_the_lines_its_own_cap_dropped(self):
        phases = [dl("08.%03d" % i, "status", "Connecting(Phase%d)" % (i % 2)) for i in range(40)]
        drop = self.DROP[:3] + phases + [dl("09.004", "status", "Connected")]
        res = self.run_seq(self.start() + [self.o(10, drop)])                  # 새 경로
        for f in res[2][1]:
            if f.kind in ("VPN_DISCONNECTED", "VPN_RECONNECTED"):
                self.assertEqual(f.evidence["daemon_lines_dropped"], len(drop) - vpn_rules.DAEMON_OPEN_MAX, f.kind)
        res = self.run_seq(self.start() + [self.o(10, drop[:-1], state="disconnected"),   # 조회 경로(열린 끊김)
                                           self.o(15, drop[-1:])])
        d = self.poll(res, 2, "VPN_DISCONNECTED")[0]
        r = self.poll(res, 3, "VPN_RECONNECTED")[0]
        self.assertEqual(d.evidence["daemon_lines_dropped"], len(drop) - 1 - vpn_rules.DAEMON_OPEN_MAX)
        self.assertEqual(r.evidence["daemon_lines_dropped"], len(drop) - vpn_rules.DAEMON_OPEN_MAX)
        # 끊김이 조회 끊김 주기의 창에서 통째로 닫히고 복구 판정은 한 창 늦게 — 직전 창에서 버린 수도 이어진다
        res = self.run_seq(self.start() + [self.o(10, drop, state="disconnected"), self.o(15)])
        r = self.poll(res, 3, "VPN_RECONNECTED")[0]
        self.assertEqual(len(r.evidence["daemon_lines"]), vpn_rules.DAEMON_OPEN_MAX)
        self.assertEqual(r.evidence["daemon_lines_dropped"], len(drop) - vpn_rules.DAEMON_OPEN_MAX)
        few = self.run_seq(self.start() + [self.o(10, self.DROP)])
        for f in few[2][1]:
            self.assertNotIn("daemon_lines_dropped", f.evidence, f.kind)

    def test_a_cycle_without_a_link_counts_and_caps_its_lines(self):
        from netmon.detect import vpn as rules
        cur = self.o(10, self.many_drops(30) + self.DROP[:3], state="disconnected", link=False)
        found, _ = rules.without_link(vpn_state("connected"), cur, {})
        d = [f for f in found if f.kind == "VPN_DISCONNECTED"][0]
        self.assertEqual(len(d.evidence["daemon_lines"]), vpn_rules.DAEMON_EVIDENCE_MAX)
        self.assertEqual(d.evidence["daemon_lines_dropped"], 63 - vpn_rules.DAEMON_EVIDENCE_MAX)
        phases = [dl("08.%03d" % i, "status", "Connecting(Phase%d)" % (i % 2)) for i in range(40)]
        cur = self.o(10, self.DROP[:3] + phases, state="disconnected", link=False)       # 열린 긴 끊김 43줄
        found, _ = rules.without_link(vpn_state("connected"), cur, {})
        d = [f for f in found if f.kind == "VPN_DISCONNECTED"][0]
        self.assertEqual(len(d.evidence["daemon_lines"]), vpn_rules.DAEMON_OPEN_MAX)
        self.assertEqual(d.evidence["daemon_lines_dropped"], 43 - vpn_rules.DAEMON_OPEN_MAX)

    # DEV-12 2회차 (검수 1회차: 시험이 고정하지 않던 셈 규칙) ─────────────────────
    def long_drop(self, start="11", n_phases=30, close=True):
        """원인 줄 둘 + 연결 단계 n_phases + (닫으면) Connected — 끊김당 20줄 상한으로 줄을 버리는 끊김."""
        lines = [dl(start + ".000", "error", "e"), dl(start + ".001", "status", "Disconnected(X)")]
        lines += [dl("%s.%03d" % (start, 10 + i), "status", "Connecting(P%d)" % (i % 2)) for i in range(n_phases)]
        if close:
            lines.append(dl("%s.900" % start, "status", "Connected"))
        return lines

    def test_the_previous_window_overflow_of_forty_is_counted_on_a_late_recovery(self):
        """직전 창 40줄 상한으로 넘기지 못한 줄도 센다(한 창 늦은 복구)."""
        drops = self.many_drops(25)                                            # 닫힌 짧은 끊김 25건 = 50줄
        res = self.run_seq(self.start() + [self.o(10, drops, state="disconnected"), self.o(15)])
        r = self.poll(res, 3, "VPN_RECONNECTED")[0]
        self.assertEqual(len(r.evidence["daemon_lines"]), vpn_rules.DAEMON_EVIDENCE_MAX)
        self.assertEqual(r.evidence["daemon_lines_dropped"], 50 - vpn_rules.DAEMON_EVIDENCE_MAX)

    def test_a_count_is_not_carried_when_the_lines_are_not(self):
        """조회가 연결인 주기의 닫힌 끊김은 다음 주기로 넘기지 않는다 — 버린 수도 넘기지 않는다(과다 표시 방지)."""
        seq = self.start() + [self.o(10, self.DROP[:3], state="disconnected"),
                              self.o(15, self.DROP[3:] + self.long_drop("12")),            # 긴 끊김 B: 줄을 버림, 조회 연결
                              self.o(20, [dl("17.000", "status", "Disconnected(NoNetwork)")], state="disconnected", link=False),
                              self.o(25, [dl("22.000", "status", "Connected")])]
        res = self.run_seq(seq)
        r = [f for f in res[5][1] if f.kind == "VPN_RECONNECTED" and f.evidence.get("link_absent")][0]
        self.assertEqual([x["text"] for x in r.evidence["daemon_lines"]], ["Disconnected(NoNetwork)", "Connected"])
        self.assertNotIn("daemon_lines_dropped", r.evidence)

    def test_forgetting_the_daemon_state_forgets_the_counts(self):
        state = {vpn_rules.DAEMON_PREV_CLOSED_DROPPED_KEY: 7, vpn_rules.DAEMON_PREV_TRANSITIONS_DROPPED_KEY: 40}
        ob = self.o(10)
        del ob.data["warp_daemon"]
        vpn_rules.warp_daemon_window(state, ob, suppress=False)
        self.assertNotIn(vpn_rules.DAEMON_PREV_CLOSED_DROPPED_KEY, state)
        self.assertNotIn(vpn_rules.DAEMON_PREV_TRANSITIONS_DROPPED_KEY, state)

    def test_a_drop_finding_counts_the_closed_drops_of_its_window(self):
        """끊김 판정(down) 증거는 그 창의 닫힌 긴 끊김이 버린 수와 열린 끊김이 버린 수를 더한다."""
        closed = self.long_drop("06")                                          # 닫힘: 33줄 → 20줄, 13 버림
        opened = self.long_drop("08", n_phases=25, close=False)                # 열림: 27줄 → 20줄, 7 버림
        res = self.run_seq(self.start() + [self.o(10, closed + opened, state="disconnected")])
        d = self.poll(res, 2, "VPN_DISCONNECTED")[0]
        self.assertEqual(d.evidence["daemon_lines_dropped"], 13 + 7 + (40 - vpn_rules.DAEMON_EVIDENCE_MAX))
        self.assertEqual(len(d.evidence["daemon_lines"]), vpn_rules.DAEMON_EVIDENCE_MAX)

    def test_a_cycle_without_a_link_counts_the_closed_drops_too(self):
        from netmon.detect import vpn as rules
        cur = self.o(10, self.long_drop("06") + [dl("09.000", "status", "Disconnected(NoNetwork)")],
                     state="disconnected", link=False)
        found, _ = rules.without_link(vpn_state("connected"), cur, {})
        d = [f for f in found if f.kind == "VPN_DISCONNECTED"][0]
        self.assertEqual(d.evidence["daemon_lines_dropped"], 13)
        self.assertEqual(len(d.evidence["daemon_lines"]), 21)

    def test_exactly_one_dropped_line_is_counted_everywhere(self):
        """상한을 딱 한 줄 넘은 경계(DEV-12 3회차 검수 [낮음]: `if dropped:` 를 `> 1` 로 바꾼 변이가 살아남았다) — 조회 경로 41줄, 새 경로
        끊김 21줄, 직전 창에서 넘긴 닫힌 끊김 41줄(상태 키로 1 이 넘어가 한 창 늦은 복구에)."""
        res = self.run_seq(self.start() + [self.o(10, self.many_drops(19) + self.DROP[:3], state="disconnected")])   # 38 + 3 = 41줄
        d = self.poll(res, 2, "VPN_DISCONNECTED")[0]
        self.assertEqual((len(d.evidence["daemon_lines"]), d.evidence.get("daemon_lines_dropped")), (40, 1))
        phases = [dl("08.%03d" % i, "status", "Connecting(Phase%d)" % (i % 2)) for i in range(17)]
        drop = self.DROP[:3] + phases + [dl("09.004", "status", "Connected")]
        self.assertEqual(len(drop), vpn_rules.DAEMON_OPEN_MAX + 1)
        res = self.run_seq(self.start() + [self.o(10, drop)])                  # 새 경로
        got = sorted((f.kind, f.evidence.get("daemon_lines_dropped")) for f in res[2][1]
                     if f.kind in ("VPN_DISCONNECTED", "VPN_RECONNECTED"))
        self.assertEqual(got, [("VPN_DISCONNECTED", 1), ("VPN_RECONNECTED", 1)])
        closed = self.many_drops(19) + [dl("09.000", "status", "Disconnected(Y)"), dl("09.100", "status", "Connecting(Z)"),
                                        dl("09.200", "status", "Connected")]                         # 닫힌 끊김 41줄
        res = self.run_seq(self.start() + [self.o(10, closed, state="disconnected"), self.o(15)])
        r = self.poll(res, 3, "VPN_RECONNECTED")[0]
        self.assertEqual((len(r.evidence["daemon_lines"]), r.evidence.get("daemon_lines_dropped")), (40, 1))

    def test_the_documented_caps_are_forty_and_twenty(self):
        """문서(docs/detections.md)가 적은 상한 값 — 조회 경로 `daemon_lines` 뒤쪽 40줄, 창당 전환 뒤쪽 20줄(DEV-12 2회차 검수 [낮음]:
        다른 시험은 상수를 이름으로만 읽어 40→30 같은 변경에도 통과했다)."""
        self.assertEqual((vpn_rules.DAEMON_EVIDENCE_MAX, vpn_rules.DAEMON_TRANSITIONS_MAX), (40, 20))
        res = self.run_seq(self.start() + [self.o(10, self.many_drops(30) + self.DROP[:3], state="disconnected")])
        d = self.poll(res, 2, "VPN_DISCONNECTED")[0]
        self.assertEqual((len(d.evidence["daemon_lines"]), d.evidence["daemon_lines_dropped"]), (40, 23))

    def test_the_other_documented_caps_keep_their_values(self):
        """문서가 적은 나머지 상한 값(FINAL 1회차 [낮음]: 시험이 상수를 이름으로만 읽어 값을 바꾼 변이가 통과했다) —
        창당 새 경로 끊김 10건(docs/detections.md, 사용자 확인 값), 원인 줄 대기 20줄·넘어온 창 200항목(같은 문서),
        읽기 4MiB·저장 글 300자·수집 쪽 보류 20줄(docs/data-sources.md)."""
        self.assertEqual((vpn_rules.DAEMON_DROPS_MAX, vpn_rules.DAEMON_PENDING_MAX, vpn_rules.DAEMON_CARRY_MAX), (10, 20, 200))
        self.assertEqual((vpnmod.WARP_DAEMON_READ_CAP, vpnmod.WARP_DAEMON_TEXT_CAP, vpnmod.WARP_DAEMON_HELD_MAX),
                         (4 * 1024 * 1024, 300, 20))

    def test_no_count_key_stays_in_the_state_when_nothing_was_dropped(self):
        """K-6 "버린 것이 없으면 키가 없다" 는 상태 파일에도 해당한다(DEV-12 2회차 검수 [정보]: 0 값 키를 남기는 변이가 살아남았다)."""
        eng = self.engine({})
        self.judge_seq(eng, self.start() + [self.o(10, self.DROP[:3], state="disconnected"), self.o(15, self.DROP[3:])])
        self.assertNotIn(vpn_rules.DAEMON_PREV_CLOSED_DROPPED_KEY, eng.state)
        self.assertNotIn(vpn_rules.DAEMON_PREV_TRANSITIONS_DROPPED_KEY, eng.state)

    def test_broken_dropped_counts_in_the_state_are_zero(self):
        for bad in (-3, "7", 2.5, True, None, [1], 10 ** 12, {}, float("nan")):
            eng = self.engine({})
            self.judge_seq(eng, self.start() + [self.o(10, self.DROP[:3], state="disconnected")])
            eng.state[vpn_rules.DAEMON_PREV_CLOSED_DROPPED_KEY] = bad
            eng.state[vpn_rules.DAEMON_PREV_TRANSITIONS_DROPPED_KEY] = bad
            out = eng.judge(self.o(15, self.DROP[3:]), 5.0)
            self.assertEqual([f for f in out if f.kind == "DETECTOR_ERROR"], [], repr(bad))
            r = [f for f in out if f.kind == "VPN_RECONNECTED"][0]
            self.assertNotIn("daemon_lines_dropped", r.evidence, repr(bad))


class TestDaemonTransitionsOnOtherFindings(_DaemonSequence, unittest.TestCase):
    """이번 또는 직전 창의 WARP 연결↔비연결 전환이 리졸버·로컬 프록시·기본 경로·터널 밖 경로 판정의 증거로 붙는다.
    등급·귀속은 그대로다 (DEV-6 — QA-8)."""

    BASE = dict(tunnel_default=("utun3",), route_counts={"en0": 1, "utun3": 1})
    CHANGES = {"RESOLVER_CHANGED": dict(resolvers=("198.51.100.53",)),
               "DNS_LOCAL_PROXY_CHANGED": dict(via_loopback=True),
               "DEFAULT_ROUTE_CHANGED": dict(gateway="192.0.2.254"),
               "ROUTES_OUTSIDE_TUNNEL": dict(route_counts={"en0": 5, "utun3": 1})}

    def seq_for(self, kind, change_at, drop_at=10, lines=None):
        seq = [self.o(0, [dl("00.000", "status", "Connected")], **self.BASE), self.o(5, **self.BASE)]
        for sec in range(10, change_at + 1, 5):
            kw = dict(self.BASE)
            if sec >= change_at:
                kw.update(self.CHANGES[kind])
            seq.append(self.o(sec, (lines if lines is not None else self.DROP) if sec == drop_at else (), **kw))
        return seq

    def finding(self, res, kind):
        return [f for f in res[-1][1] if f.kind == kind][0]

    def test_a_transition_in_this_window_is_attached_and_nothing_else_changes(self):
        for kind in self.CHANGES:
            seq = self.seq_for(kind, change_at=10)
            f = self.finding(self.run_seq(seq), kind)
            self.assertEqual([x["text"] for x in f.evidence["daemon_transitions"]],
                             ["Disconnected(InternalTunnelError)", "Connected"], kind)
            for o in seq:
                del o.data["warp_daemon"]
            plain = self.finding(self.run_seq(seq), kind)
            self.assertNotIn("daemon_transitions", plain.evidence, kind)
            self.assertEqual((f.severity, f.attribution, f.confidence, f.summary),
                             (plain.severity, plain.attribution, plain.confidence, plain.summary), kind)
            self.assertEqual({k: v for k, v in f.evidence.items() if k != "daemon_transitions"}, plain.evidence, kind)

    def test_a_transition_in_the_previous_window_is_attached_but_not_two_windows_ago(self):
        for kind in self.CHANGES:
            f = self.finding(self.run_seq(self.seq_for(kind, change_at=15)), kind)
            self.assertEqual(len(f.evidence["daemon_transitions"]), 2, kind)
            f = self.finding(self.run_seq(self.seq_for(kind, change_at=20)), kind)
            self.assertNotIn("daemon_transitions", f.evidence, kind)

    def test_a_broken_dropped_count_in_the_state_never_costs_the_finding(self):
        """깨진 `warp_daemon_prev_transitions_dropped` 가 이 판정들에서 예외를 내지 않고 표시도 붙이지 않는다(DEV-12 2회차 검수 [정보]:
        이 값의 검증 두 자리를 모두 뺀 변이가 전체 시험을 통과했다 — 이 값을 읽는 판정은 전환 증거를 붙이는 이 넷뿐이다)."""
        for bad in (-3, "7", 2.5, True, None, [1], 10 ** 12, {}, float("nan")):
            for kind in self.CHANGES:
                seq = self.seq_for(kind, change_at=15)
                eng = self.engine({})
                self.judge_seq(eng, seq[:-1])
                eng.state[vpn_rules.DAEMON_PREV_TRANSITIONS_DROPPED_KEY] = bad
                out = eng.judge(seq[-1], 5.0)
                self.assertEqual([f for f in out if f.kind == "DETECTOR_ERROR"], [], (kind, repr(bad)))
                f = [f for f in out if f.kind == kind][0]
                self.assertEqual(len(f.evidence["daemon_transitions"]), 2, (kind, repr(bad)))
                self.assertNotIn("daemon_transitions_dropped", f.evidence, (kind, repr(bad)))

    def test_phase_changes_inside_an_open_drop_are_not_transitions(self):
        # 창 10 에서 끊김이 열리고(전환), 창 15 는 연결 단계만 바뀌고(전환 아님), 변화는 창 20 — 직전 창(15)에 전환 없음
        seq = self.seq_for("RESOLVER_CHANGED", change_at=20, drop_at=10, lines=self.DROP[2:3])
        seq[-2].data["warp_daemon"]["lines"] = [dl("12.000", "status", "Connecting(CheckingNetwork)")]
        f = self.finding(self.run_seq(seq), "RESOLVER_CHANGED")
        self.assertNotIn("daemon_transitions", f.evidence)


    # DEV-6 2회차 (검수 1회차 지적) ─────────────────────────────────────────
    def polled_seq(self, kind, lines=True):
        """조회로 잡힌 끊김: 10초 조회 disconnected(창에 Disconnected), 15초 조회 connected(창에 Connected)와 그 주기의 변화."""
        seq = [self.o(0, [dl("00.000", "status", "Connected")], **self.BASE), self.o(5, **self.BASE)]
        up = dict(self.BASE)
        if kind == "RESOLVER_CHANGED":
            # VPN 이 올라오며 리졸버가 루프백 하나가 됨 — VPN 전환으로 설명되는 모양(dns.explained_by_vpn → vpn_change 귀속)
            up.update(resolvers=("127.0.2.2",), via_loopback=True)
        elif kind != "DEFAULT_ROUTE_CHANGED":
            up.update(self.CHANGES[kind])
        seq.append(self.o(10, [dl("07.493", "status", "Disconnected(InternalTunnelError)")], state="disconnected",
                          **self.BASE))
        seq.append(self.o(15, [dl("12.000", "status", "Connected")], **up))
        if kind == "DEFAULT_ROUTE_CHANGED":
            # 터널 기본 경로만 빠졌다 돌아옴 — VPN 오르내림으로 설명되는 모양(route.py 의 vpn_change 귀속)
            for i, ob in enumerate(seq):
                if i != 2:
                    ob.data["route"]["default4"].append(
                        {"gateway": {"id": "ipv4", "v": "192.0.2.2"}, "iface": "utun3", "flags": "UGScg"})
        return seq

    def same_but_the_evidence(self, seq, kind):
        f = self.finding(self.run_seq(seq), kind)
        for o in seq:
            del o.data["warp_daemon"]
        plain = self.finding(self.run_seq(seq), kind)
        self.assertEqual((f.severity, f.attribution, f.confidence, f.summary),
                         (plain.severity, plain.attribution, plain.confidence, plain.summary), kind)
        self.assertEqual({k: v for k, v in f.evidence.items() if k != "daemon_transitions"}, plain.evidence, kind)
        return f

    def test_a_poll_caught_drop_keeps_the_attribution_and_gets_the_transitions(self):
        attributed = []
        for kind in self.CHANGES:
            f = self.same_but_the_evidence(self.polled_seq(kind), kind)
            self.assertEqual([x["text"] for x in f.evidence["daemon_transitions"]],
                             ["Disconnected(InternalTunnelError)", "Connected"], kind)
            if f.attribution:
                attributed.append(kind)
        # 귀속이 붙는 판정이 실제로 있어야 이 시험이 "귀속 보존" 을 본다(dns·route 두 판정기 모두)
        for kind in ("RESOLVER_CHANGED", "DNS_LOCAL_PROXY_CHANGED", "DEFAULT_ROUTE_CHANGED", "ROUTES_OUTSIDE_TUNNEL"):
            self.assertIn(kind, attributed)

    def test_a_gap_or_a_restart_cycle_keeps_the_finding_and_gets_the_transitions(self):
        for kind in self.CHANGES:
            for label, extra in (("공백", dict(sec=100)), ("재시작", dict(sec=10, start=True))):
                seq = [self.o(0, [dl("00.000", "status", "Connected")], **self.BASE), self.o(5, **self.BASE)]
                kw = dict(self.BASE)
                kw.update(self.CHANGES[kind])
                seq.append(self.o(extra["sec"], self.DROP, start=extra.get("start", False), **kw))
                f = self.same_but_the_evidence(seq, kind)
                self.assertEqual(len(f.evidence["daemon_transitions"]), 2, (kind, label))

    def test_broken_new_state_keys_never_cost_the_findings_of_the_cycle(self):
        """ADV-6: 깨진 `warp_daemon_prev_transitions`·`warp_daemon_prev_closed` 로도 리졸버·경로 판정이 사라지지 않는다."""
        bad_values = ["abc", [5], 5, None, {"x": 1}, [{"ts": "x"}] * 1000, [[1, 2]], ["x" * 10 ** 6],
                     [{"ts": "2026-01-01T00:00:01.000Z", "kind": "status", "text": "x" * 10 ** 6}]]
        for kind in self.CHANGES:
            for bad in bad_values:
                eng = self.engine({vpn_rules.DAEMON_STATE_KEY: {"state": "Connected", "pending": [], "open_since": None,
                                                                "open_lines": [], "open_dropped": 0},
                                   vpn_rules.DAEMON_POLLS_KEY: ["connected"],
                                   vpn_rules.DAEMON_PREV_TRANSITIONS_KEY: bad,
                                   vpn_rules.DAEMON_PREV_CLOSED_KEY: bad})
                eng.prev = self.o(5, **self.BASE)
                kw = dict(self.BASE)
                kw.update(self.CHANGES[kind])
                out = eng.judge(self.o(10, **kw), 5.0)
                self.assertEqual([f for f in out if f.kind == "DETECTOR_ERROR"], [], (kind, repr(bad)[:40]))
                self.assertIn(kind, [f.kind for f in out], (kind, repr(bad)[:40]))
                json.dumps(eng.state)

    def test_a_malformed_window_gives_no_transitions_and_no_exception(self):
        import types
        for window in ({"prev_transitions": "abc", "transitions": [5, {"ts": "x"}]}, {"transitions": 5},
                       {"prev_transitions": [{"ts": "2026-01-01T00:00:01.000Z", "kind": "status", "text": 3}]}):
            self.assertEqual(vpn_rules.daemon_transitions(types.SimpleNamespace(warp_daemon=window)), [], window)

    def test_each_window_keeps_its_last_twenty_transitions(self):
        lines = []
        for i in range(30):
            lines += [dl("05.%03d" % (i * 20), "status", "Disconnected(X)"), dl("05.%03d" % (i * 20 + 10), "status", "Connected")]
        f = self.finding(self.run_seq(self.seq_for("RESOLVER_CHANGED", change_at=10, lines=lines)), "RESOLVER_CHANGED")
        self.assertEqual(f.evidence["daemon_transitions"], lines[-vpn_rules.DAEMON_TRANSITIONS_MAX:])
        state = {}
        vpn_rules.warp_daemon_window(state, self.o(0, [dl("00.000", "status", "Connected")] + lines), suppress=False)
        self.assertEqual(state[vpn_rules.DAEMON_PREV_TRANSITIONS_KEY], lines[-vpn_rules.DAEMON_TRANSITIONS_MAX:])   # 상태 파일도 상한

    def test_the_first_broadcast_from_an_unknown_state_is_not_a_transition(self):
        seq = [self.o(0, [dl("00.000", "status", "Disconnected(X)")], **self.BASE),
               self.o(5, [dl("04.000", "status", "Connected")], resolvers=("198.51.100.53",), **self.BASE)]
        f = self.finding(self.run_seq(seq), "RESOLVER_CHANGED")
        self.assertEqual([x["text"] for x in f.evidence["daemon_transitions"]], ["Connected"])
        seq = [self.o(0, [dl("00.000", "status", "Connected")], **self.BASE),
               self.o(5, resolvers=("198.51.100.53",), **self.BASE)]
        self.assertNotIn("daemon_transitions", self.finding(self.run_seq(seq), "RESOLVER_CHANGED").evidence)

    def test_only_the_four_kinds_get_the_transitions(self):
        seq = self.seq_for("RESOLVER_CHANGED", change_at=10)
        seq[-1].data["dns"]["proxy"] = {"HTTPEnable": "1"}
        res = self.run_seq(seq)
        other = [f for f in res[-1][1] if f.kind in ("PROXY_ENABLED", "PROXY_SETTINGS_CHANGED")]
        self.assertTrue(other)
        for f in other:
            self.assertNotIn("daemon_transitions", f.evidence)

    def test_a_cycle_without_a_link_does_not_erase_the_previous_window(self):
        seq = self.seq_for("RESOLVER_CHANGED", change_at=10)[:-1]
        seq.append(self.o(10, self.DROP, **self.BASE))
        seq.append(self.o(15, link=False, **self.BASE))
        kw = dict(self.BASE)
        kw.update(self.CHANGES["RESOLVER_CHANGED"])
        seq.append(self.o(20, **kw))
        f = self.finding(self.run_seq(seq), "RESOLVER_CHANGED")
        self.assertEqual([x["text"] for x in f.evidence["daemon_transitions"]],
                         ["Disconnected(InternalTunnelError)", "Connected"])


    # DEV-6 3회차 (검수 2회차 지적) ─────────────────────────────────────────
    def change(self, sec, lines=(), kind="RESOLVER_CHANGED", n=1, **extra):
        kw = dict(self.BASE)
        kw.update(resolvers=("198.51.100.%d" % (50 + n),))
        kw.update(extra)
        return self.o(sec, lines, **kw)

    def texts_at(self, res, i):
        f = [f for f in res[i][1] if f.kind == "RESOLVER_CHANGED"][0]
        return [x["text"] for x in f.evidence.get("daemon_transitions", [])]

    def test_transitions_read_in_a_cycle_without_a_link_are_this_window_and_then_the_previous(self):
        """링크가 끊긴 주기에 찍힌 끊김(넘어온 창)은 링크가 돌아온 판정 주기의 "이번 창" 이고, 그다음 판정 주기의 "직전 창" 이다(D1·D2)."""
        drop = [dl("07.493", "status", "Disconnected(NoNetwork)"), dl("08.500", "status", "Connected")]
        seq = [self.o(0, [dl("00.000", "status", "Connected")], **self.BASE), self.o(5, **self.BASE),
               self.o(10, drop, link=False, **self.BASE), self.change(15, n=1), self.change(20, n=2), self.change(25, n=3)]
        res = self.run_seq(seq)
        want = ["Disconnected(NoNetwork)", "Connected"]
        self.assertEqual(self.texts_at(res, 3), want)
        self.assertEqual(self.texts_at(res, 4), want)
        self.assertEqual(self.texts_at(res, 5), [])

    def test_a_suppressed_cycle_keeps_and_passes_on_its_transitions(self):
        """측정 공백·재시작 주기도 이번·직전 창의 전환을 붙이고(G·R), 그 주기의 전환을 다음 판정 주기에 넘긴다(L)."""
        want = ["Disconnected(InternalTunnelError)", "Connected"]
        base = [self.o(0, [dl("00.000", "status", "Connected")], **self.BASE), self.o(5, **self.BASE)]
        # G: 공백 주기에 직전 창 전환
        res = self.run_seq(base + [self.o(10, self.DROP, **self.BASE), self.change(100)])
        self.assertEqual(self.texts_at(res, 3), want)
        # R: 재시작 주기에 직전 창 전환(state.json 을 거친 것처럼 이어진 상태)
        res = self.run_seq(base + [self.o(10, self.DROP, **self.BASE), self.change(15, start=True)])
        self.assertEqual(self.texts_at(res, 3), want)
        # L: 공백 주기에 읽은 전환이 다음 판정 주기의 직전 창으로
        late = [dl("37.493", "status", "Disconnected(InternalTunnelError)"),
                dl("38.500", "status", "Connected")]
        res = self.run_seq(base + [self.o(40, late, **self.BASE), self.change(45)])
        self.assertEqual(self.texts_at(res, 3), want)


    def test_every_kind_says_how_many_transitions_were_dropped(self):
        lines = []
        for i in range(30):
            lines += [dl("05.%03d" % (i * 20), "status", "Disconnected(X)"), dl("05.%03d" % (i * 20 + 10), "status", "Connected")]
        for kind in self.CHANGES:
            f = self.finding(self.run_seq(self.seq_for(kind, change_at=10, lines=lines)), kind)
            self.assertEqual(f.evidence["daemon_transitions_dropped"], 60 - vpn_rules.DAEMON_TRANSITIONS_MAX, kind)

    def test_transitions_carried_from_a_cycle_without_a_link_count_in_the_window(self):
        carried = []
        for i in range(15):
            carried += [dl("07.%03d" % (i * 20), "status", "Disconnected(X)"), dl("07.%03d" % (i * 20 + 10), "status", "Connected")]
        own = []
        for i in range(5):
            own += [dl("12.%03d" % (i * 20), "status", "Disconnected(Y)"), dl("12.%03d" % (i * 20 + 10), "status", "Connected")]
        seq = [self.o(0, [dl("00.000", "status", "Connected")], **self.BASE), self.o(5, **self.BASE),
               self.o(10, carried, link=False, **self.BASE), self.change(15, own, n=1)]
        f = [f for f in self.run_seq(seq)[-1][1] if f.kind == "RESOLVER_CHANGED"][0]
        self.assertEqual(len(f.evidence["daemon_transitions"]), vpn_rules.DAEMON_TRANSITIONS_MAX)
        self.assertEqual(f.evidence["daemon_transitions_dropped"], 40 - vpn_rules.DAEMON_TRANSITIONS_MAX)

    def test_a_read_failure_or_a_reset_keeps_the_previous_window_and_forgets_older(self):
        """DEV-14 (DEV-6 3회차 [낮음] J·N·L): 이번 창이 읽기 실패·reset 이어도 직전 판정 창의 전환은 붙고, 그다음 주기에는 두 창 전이라 붙지 않는다."""
        want = ["Disconnected(InternalTunnelError)", "Connected"]
        base = [self.o(0, [dl("00.000", "status", "Connected")], **self.BASE), self.o(5, **self.BASE),
                self.o(10, self.DROP, **self.BASE)]
        for label, extra in (("읽기 실패", dict(read="unreadable")), ("없음", dict(read="missing")), ("reset", dict(reset=True))):
            seq = base + [self.change(15, n=1, **extra), self.change(20, n=2)]
            res = self.run_seq(seq)
            self.assertEqual(self.texts_at(res, 3), want, label)
            self.assertEqual(self.texts_at(res, 4), [], label)

    def test_transitions_before_a_reset_in_a_carried_window_are_kept(self):
        """DEV-14 (D): 넘어온 창 가운데 reset 이 있어도 그 앞의 전환은 이번 창의 전환이다."""
        seq = [self.o(0, [dl("00.000", "status", "Connected")], **self.BASE), self.o(5, **self.BASE),
               self.o(10, self.DROP, link=False, **self.BASE), self.o(15, link=False, reset=True, **self.BASE),
               self.change(20, n=1)]
        res = self.run_seq(seq)
        self.assertEqual(self.texts_at(res, 4), ["Disconnected(InternalTunnelError)", "Connected"])

    def test_exactly_one_dropped_transition_is_counted(self):
        """한 창의 21번째 전환(DEV-12 3회차 검수 [낮음]: 경계 1 을 고정하는 시험이 없었다) — 네 판정의 이번 창과, 다음 판정 주기의 직전 창
        (상태 키로 넘어간 1)."""
        lines = [dl("05.%03d" % (i * 10), "status", "Disconnected(X)" if i % 2 == 0 else "Connected") for i in range(21)]
        for kind in self.CHANGES:
            f = self.finding(self.run_seq(self.seq_for(kind, change_at=10, lines=lines)), kind)
            self.assertEqual((len(f.evidence["daemon_transitions"]), f.evidence.get("daemon_transitions_dropped")), (20, 1), kind)
        seq = self.seq_for("RESOLVER_CHANGED", change_at=10, lines=lines)
        seq.append(self.change(15, n=4))
        nxt = [f for f in self.run_seq(seq)[-1][1] if f.kind == "RESOLVER_CHANGED"][0]
        self.assertEqual(nxt.evidence.get("daemon_transitions_dropped"), 1)

    def test_a_truncated_window_of_transitions_says_how_many_were_dropped(self):
        lines = []
        for i in range(30):
            lines += [dl("05.%03d" % (i * 20), "status", "Disconnected(X)"), dl("05.%03d" % (i * 20 + 10), "status", "Connected")]
        seq = self.seq_for("RESOLVER_CHANGED", change_at=10, lines=lines)
        seq.append(self.change(15, n=4))                                       # 다음 판정 주기 — 직전 창으로
        res = self.run_seq(seq)
        now = [f for f in res[-2][1] if f.kind == "RESOLVER_CHANGED"][0]
        nxt = [f for f in res[-1][1] if f.kind == "RESOLVER_CHANGED"][0]
        self.assertEqual(now.evidence["daemon_transitions_dropped"], 60 - vpn_rules.DAEMON_TRANSITIONS_MAX)
        self.assertEqual(nxt.evidence["daemon_transitions_dropped"], 60 - vpn_rules.DAEMON_TRANSITIONS_MAX)
        few = self.finding(self.run_seq(self.seq_for("RESOLVER_CHANGED", change_at=10)), "RESOLVER_CHANGED")
        self.assertNotIn("daemon_transitions_dropped", few.evidence)


def enginemod_replay(cfg, seq):
    from netmon import engine as enginemod
    return enginemod.replay(cfg, seq)


class TestWarpStatusParsing(unittest.TestCase):
    """warp-cli 의 `Status update:` 값을 상태로 옮긴다.

    **"disconnected" 에도 "connect" 가 들어 있다.** 부분 문자열로 먼저 가르면
    `Disconnected` 가 `connecting` 으로 옮겨진다. 확정된 것은 이 코드 동작이다
    (아래 첫 검사).

    기록에서 그 흔적으로 보이는 것은 사유가 `Settings Changed` 인 454주기다
    (2026-09-16~22 UTC 전체). `connecting` 으로 기록됐지만 같은 사유가 한 번에
    최장 15분 32초(184주기) 이어졌고, 연결 단계 사유가 이어진 구간은 최장
    16주기(46초)였다. 끊김 상태의 사유라는 근거는 **정황**이다 — warp-cli
    바이너리에 `DisconnectedReason::SettingsChanged` 라는 형 이름이 있다. WARP
    데몬 로그(2026-09-22T14:40Z 이후만 남음)에는 그 사유가 한 번도 없어 대조하지
    못했고, 표본은 상태 원문을 저장하지 않는다.

    사유가 `Manual Disconnection` 인 7주기는 **판단하지 못한다.** 데몬 로그에서
    확인한 `Disconnected(Manual)` 5건(2026-09-22T15:07Z~2026-09-23T03:19Z)은
    모두 11ms 안에 `Connecting(CheckingNetwork)` 로 넘어갔으므로, 5초 간격
    표본이 잡은 그 주기는 연결 단계였을 수도 있다.

    `Settings Changed` 주기에도 품질 축 요약문은 기록된 값을 인용해 "터널 재협상
    중(공급자 상태 connecting)" 이라고 적었다(2026-09-22T14:33:44Z 와
    2026-09-22T14:34:04Z 의 두 판정). docs/data-sources.md 의 414 는 2026-09-22
    19시(한국 시각) 시점까지 센 값이라 그 뒤의 이 구간 40주기가 빠져 있다.

    `Unable`(No Network·happy eyeballs 실패 등)은 전과 같이 `disconnected` 다.
    """

    def _status(self, text):
        from netmon.util import CmdResult
        calls = []

        def fake_run(argv, timeout=None, stdin=""):
            calls.append(list(argv))
            if "status" in argv:
                return CmdResult(argv, 0, text, "")
            return CmdResult(argv, 0, TestWarpModeParsing.SETTINGS, "")

        orig = vpnmod.run
        vpnmod.run = fake_run
        try:
            return vpnmod.Warp().status(), calls
        finally:
            vpnmod.run = orig

    def test_each_reported_state_maps_to_its_own_value(self):
        for text, expect in (
                ("Status update: Connected\nNetwork: healthy\n", "connected"),
                ("Status update: Connecting\nReason: Performing connectivity checks\n",
                 "connecting"),
                ("Status update: Disconnected\nReason: Settings Changed\n", "disconnected"),
                ("Status update: Disconnected\nReason: Manual Disconnection\n",
                 "disconnected"),
                ("Status update: Unable\nReason: No Network\n", "disconnected")):
            st, _ = self._status(text)
            self.assertEqual(st.state, expect, text)

    def test_a_disconnect_keeps_its_reason(self):
        st, _ = self._status("Status update: Disconnected\nReason: Settings Changed\n")
        self.assertEqual(st.reason, "Settings Changed")

    def test_the_mode_is_read_only_when_connected(self):
        """비연결에서는 모드를 조회하지 않아 터널 여부가 `None`(모름)으로 남는다."""
        for text in ("Status update: Disconnected\n", "Status update: Connecting\n",
                     "Status update: Unable\n"):
            st, calls = self._status(text)
            self.assertIsNone(st.tunnel, text)
            self.assertFalse([c for c in calls if "settings" in c], text)
        st, calls = self._status("Status update: Connected\n")
        self.assertIs(st.tunnel, False)      # SETTINGS 의 모드가 DnsOverTls
        self.assertTrue([c for c in calls if "settings" in c])


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
    끊긴 적이 없으니 상태 전환 판정에 걸리지 않아, 터널의 보호가 사라진 채로
    조용했다."""

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
    보통 한 주기 늦는다(AC-4c). **둘이 실제로 어떤 주기에 겹치는지는 재지
    않았다** — 이 기능을 켜고 돌려 본 적이 없다. 아래 픽스처는 합성이고,
    증거를 싣는 규칙만 고정한다. (앞서 이 자리에 "링크가 없어 판정을 건너뛴
    주기가 사이에 끼는 경우" 라고 적혀 있었으나 그 모양은 오히려 판정이
    억제된다 — `without_link` 가 남긴 `vpn_down_reported` 를 `already_reported`
    가 읽는다. tests/test_from_real_logs.py 의
    `test_the_cycle_the_link_comes_back_does_not_report_it_again` 참조.)
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
        # "연결 끊김" 으로 적지 않는다 — 이 픽스처의 warp connecting 은 다시 맺는 중인 상태다.
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

        이 주기에 남는 것은 공급자가 보고한 값과 "링크가 없었다", 그리고 WARP 면
        데몬 로그에서 읽은 줄(작업 2026-09-23-warp-daemon-log AC-7 — 관측에 그
        자료가 없으면 "absent" 와 빈 목록)뿐이다. 첫 홉·엔드포인트·귀속은 재지도
        계산하지도 않았다.
        """
        f = self._run()[0][0]
        self.assertEqual(set(f.evidence), {"provider", "provider_state",
                                           "provider_reason", "prev_state",
                                           "link_absent", "down_since",
                                           "daemon_read", "daemon_lines"})
        self.assertEqual((f.evidence["daemon_read"], f.evidence["daemon_lines"]), ("absent", []))
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
        """문구만 고치고 동작을 바꾸지 않았다 — 근거는 여전히 공급자 값뿐이다.

        (데몬 로그 증거 두 필드는 공급자 dict 밖에서 따로 읽은 것이다 — AC-7.)
        """
        f = self._finding()
        self.assertEqual(set(f.evidence), {"provider", "provider_state",
                                           "provider_reason", "prev_state",
                                           "link_absent", "down_since",
                                           "daemon_read", "daemon_lines"})
        # Wi-Fi 를 읽었다면 보호 상실 판정이 났을 것이다. 나지 않는다.
        found, _ = vpn_rules.without_link(vpn_state("connected"),
                                          self._absent(), {})
        self.assertEqual([x.kind for x in found], ["VPN_DISCONNECTED"])


# --- 완전한 관측이 한 번도 보지 못한 끊김의 끝 (AC-8, AC-16) ---

DOWN_SINCE = "2026-01-01T00:00:05Z"
BACK_AT = "2026-01-01T00:01:05Z"


class TestTheEndOfAnOutageCompleteObservationsNeverSaw(unittest.TestCase):
    """링크가 없던 주기에 시작해, 완전한 관측이 돌아왔을 때는 이미 끝나 있던 끊김.

    `detect` 는 직전 **완전** 관측과 견주므로 그런 끊김은 `was == now ==
    connected` 로 보여 전환이 없다. 2026-09-21 하루치를 재생하면 끊김 17 건에
    복구 13 건이었고, 그 끊김의 기록(`vpn_down_since`·`vpn_down_pending`·
    `vpn_down_reported`)은 같은 주기 끝의 `baseline.update_vpn_down` 이 지워
    총 끊긴 시간과 미관측 시간이 어디에도 남지 않았다.

    **관측은 합성이다.** 재현한 것은 상태와 주기의 짜임새다.
    """

    def _state(self, since=DOWN_SINCE, mark=DOWN_SINCE, unmeasured=None,
               pending=False):
        state = {}
        if pending:
            state["vpn_down_pending"] = {"warp": {"since": since,
                                                  "unmeasured": unmeasured or 0.0}}
        else:
            state["vpn_down_since"] = {"warp": since}
            if unmeasured is not None:
                state["vpn_down_unmeasured"] = {"warp": unmeasured}
        if mark is not None:
            state["vpn_down_reported"] = {"warp": mark}
        return state

    def _judge(self, state, was="connected", now="connected", ts=BACK_AT):
        prev = obs(ts="2026-01-01T00:00:00Z", vpn=vpn_state(was))
        cur = obs(ts=ts, vpn=vpn_state(now))
        ctx = Context(elapsed=5.0, interval=5.0, features=ON, state=state,
                      attributions=[], network=network_key(cur))
        return vpn_rules.detect(prev, cur, ctx)

    def _finding(self, **kw):
        found = self._judge(self._state(**kw))
        self.assertEqual([f.kind for f in found], ["VPN_RECONNECTED"])
        return found[0]

    def test_the_recovery_keeps_the_kind_and_grade_it_has_elsewhere(self):
        f = self._finding()
        self.assertEqual((f.kind, f.axis, f.severity, f.confidence),
                         ("VPN_RECONNECTED", "quality", "info", "confirmed"))

    def test_the_summary_says_complete_observations_never_saw_it(self):
        f = self._finding()
        self.assertEqual(f.summary,
                         msg.VPN_RECONNECTED_NO_LINK % ("warp",
                                                        msg.VPN_SINCE % "00:00:05"))
        # 평소 복구 판정의 문장과 섞이지 않는다.
        self.assertNotIn(msg.VPN_RECONNECTED % ("warp", ""), f.summary)

    def test_the_three_time_fields_are_all_there(self):
        """AC-8 이 요구한 증거 필드. DEV-2 가 만든 것을 그대로 쓴다.

        WARP 면 데몬 로그 증거 두 필드가 더 붙는다(작업 2026-09-23-warp-daemon-log AC-7).
        """
        f = self._finding(unmeasured=30.0)
        self.assertEqual(set(f.evidence), {"provider", "down_since",
                                           "down_seconds", "unmeasured_seconds",
                                           "link_absent", "daemon_read", "daemon_lines"})
        self.assertEqual((f.evidence["daemon_read"], f.evidence["daemon_lines"]), ("absent", []))
        self.assertEqual(f.evidence["down_since"], DOWN_SINCE)
        self.assertEqual(f.evidence["down_seconds"], 60.0)
        self.assertEqual(f.evidence["unmeasured_seconds"], 30.0)
        self.assertIs(f.evidence["link_absent"], True)

    def test_the_total_and_the_unmeasured_time_are_written_together(self):
        with_gap = self._finding(unmeasured=30.0)
        self.assertIn(msg.VPN_SINCE_UNMEASURED % ("00:00:05", "1분", "30초"),
                      with_gap.summary)
        # 공백이 없으면 종전 형태(시작 시각)다 — 평소 복구 판정과 같은 문구다.
        without = self._finding()
        self.assertEqual(without.evidence["unmeasured_seconds"], 0.0)
        self.assertIn(msg.VPN_SINCE % "00:00:05", without.summary)

    def test_a_record_without_the_mark_says_nothing(self):
        """표시가 없으면 링크 없는 주기에 알린 끊김이라고 말할 수 없다.

        기록만 보고 알리면, 저장된 상태를 물려받은 주기처럼 링크와 무관하게
        남아 있던 기록까지 "링크가 없던 끊김" 으로 적게 된다.
        """
        self.assertEqual(self._judge(self._state(mark=None)), [])

    def test_a_mark_left_from_another_outage_says_nothing(self):
        self.assertEqual(self._judge(self._state(mark="2026-01-01T09:00:00Z")), [])

    def test_a_broken_state_does_not_raise(self):
        """상태 파일은 손으로 고칠 수 있고 재시작을 건너뛰어 남는다.

        `ctx.state` 자체가 dict 가 아닌 경우는 여기서 보지 않는다 — 같은
        판정기의 다른 갈래(`_tunnel_off_findings`)가 이미 dict 를 전제하고,
        엔진은 언제나 dict 를 넘긴다(netmon/engine.py 의 `Context`).
        """
        for state in ({}, {"vpn_down_reported": "x"},
                      {"vpn_down_since": {"warp": 5}, "vpn_down_reported": {"warp": 5}},
                      {"vpn_down_since": {"warp": "x"}, "vpn_down_reported": {"warp": "x"}},
                      {"vpn_down_since": {"warp": DOWN_SINCE},
                       "vpn_down_reported": {"warp": None}}):
            with self.subTest(state=state):
                self.assertEqual(self._judge(state), [])

    def test_a_record_kept_for_the_next_judgement_is_read_too(self):
        """공급자가 링크 없는 주기에 이미 올라왔으면 기록이 보관분으로 옮겨진다."""
        f = self._finding(pending=True, unmeasured=20.0)
        self.assertEqual(f.evidence["down_since"], DOWN_SINCE)
        self.assertEqual(f.evidence["unmeasured_seconds"], 20.0)

    def test_the_endpoint_tally_rides_along_here_too(self):
        state = self._state()
        state[vpnmod.ENDPOINT_PROBES_KEY] = {"warp": {"shots": 12, "capped": True}}
        f = self._judge(state)[0]
        self.assertEqual((f.evidence["tunnel_endpoint_shots"],
                          f.evidence["tunnel_endpoint_cap_reached"]), (12, True))

    def test_it_does_not_name_the_state_the_provider_was_in(self):
        """끊긴 동안의 공급자 상태는 이 판정에 전달되지 않는다 (AC-9 와 같은 기준).

        비교 대상인 직전 완전 관측은 끊기기 **전**이라 `connected` 이고,
        링크가 없던 주기의 상태는 여기까지 오지 않는다. 읽지 않은 값을 적지
        않으므로 `prev_state` 도 없다.
        """
        for code in ("ko", "en"):
            with self.subTest(lang=code):
                text = messages.get("VPN_RECONNECTED_NO_LINK", code)
                self.assertNotIn("disconnected", text)
                self.assertNotIn("connecting", text)
        self.assertNotIn("prev_state", self._finding().evidence)

    def test_a_provider_that_is_still_down_gets_nothing(self):
        self.assertEqual(self._judge(self._state(), was="disconnected",
                                     now="disconnected"), [])

    def test_the_recovery_that_a_transition_does_show_is_untouched(self):
        """전환이 보이는 복구는 종전 그대로다. 표시가 남아 있어도 같다."""
        found = self._judge(self._state(), was="disconnected")
        self.assertEqual([f.kind for f in found], ["VPN_RECONNECTED"])
        f = found[0]
        self.assertEqual(f.summary,
                         msg.VPN_RECONNECTED % ("warp", msg.VPN_SINCE % "00:00:05"))
        self.assertEqual(f.evidence["prev_state"], "disconnected")
        self.assertNotIn("link_absent", f.evidence)


class TestSummariesDoNotClaimTrafficLeftTheTunnel(unittest.TestCase):
    """요약문이 **관측하지 않은 트래픽 흐름**을 단정하지 않는다.

    `VPN_PROTECTION_LOST`·`VPN_PROTECTION_LOST_SAE`·`VPN_TUNNEL_OFF` 는
    "트래픽이 터널 밖으로 나감" 이라고 적고 있었다. 이 도구는 **사용자 트래픽**을
    재지 않는다 — `netmon/collect/` 의 수집기 일곱(iface·arp·dhcp·route·dns·wifi·
    link)이 읽는 것 중 바이트·흐름·연결 수는 없다. 세는 값이 있기는 하다 — 이
    도구가 직접 쏜 ping 의 발 수(`netmon/collect/link.py`), 커널의 ARP 프레임
    계수(`netmon/collect/arp.py` 의 `netstat -s -p arp`), 인터페이스별 경로 수
    (`netmon/collect/route.py`) — 그러나 어느 것도 무엇이 어느 경로로 나갔는지는
    말하지 못한다. 두 판정의 증거 필드에도 경로나 트래픽 값이 없다 —
    `VPN_PROTECTION_LOST` 는 provider·wifi_security·security_kind·
    passively_readable·user_action, `VPN_TUNNEL_OFF` 는 provider·mode·
    wifi_security·security_kind·passively_readable.

    2026-09-22 기록에서 그 단정이 관측과 어긋난 실례가 나왔다: 한 공급자에
    대해 이 문장이 발행된 주기의 표본에서 **다른 공급자는 `connected` 이고
    터널을 세우는 모드**였다. 판정은 공급자별로 돌며 다른 공급자의 터널
    여부를 보지 않는다. 그 단정이 틀렸음을 증명하는 것은 아니고, 뒷받침하는
    관측이 없다는 것을 보인다.

    **보호 상실은 터널이 서 있는지도 말하지 않는다.** 그 값(`vpn.<공급자>.tunnel`)
    은 이 판정이 읽지 않고, 판정 시점에는 언제나 `None` 이다 — 공급자 구현이
    연결 상태일 때만 모드를 조회한다(`TestWarpStatusParsing.test_the_mode_is_
    read_only_when_connected` 가 그 코드를 돌려 본다). 그 필드의 정의는 `None`
    을 "모른다" 로 못박고 모르는 것을 보호 없음으로 적지 말라고 한다
    (netmon/vpn/__init__.py 의 `VpnStatus`).

    **터널 없는 모드는 "이 공급자의 보호가 없다" 고 말하지 않는다.** 그 판정이
    나는 모드는 DNS only 모드이고(netmon/vpn/__init__.py 의 `warp_tunnel_for`),
    그 모드에서 공급자는 DNS 를 암호화해 받는다.

    말해도 되는 것은 남긴다: 공급자가 보고한 **연결** 상태, 터널 없는 모드라는
    사실(모드 이름), 이 네트워크가 같은 L2 에서 수동으로 읽히는 곳인지
    (`wifi.security` 분류).
    """

    # 흐름을 단정하지 않는 문구들. 보호 상실 요약문은 머리말 + 본문이다.
    NAMES = ("VPN_PROTECTION_LOST_HEAD", "VPN_PROTECTION_LOST_HEAD_RENEGOTIATING",
             "VPN_PROTECTION_LOST", "VPN_PROTECTION_LOST_SAE",
             "VPN_PROTECTION_LOST_UNKNOWN", "VPN_TUNNEL_OFF")
    FORBIDDEN = {"ko": ("터널 밖으로",), "en": ("outside the tunnel",)}
    # 보호 상실은 머리말·본문 어디서도 터널을 말하지 않는다 — 공급자가 보고하는
    # 것은 연결 상태뿐이다. `VPN_TUNNEL_OFF` 는 다르다 — 그 판정은 `tunnel is
    # False` 를 읽고 난다.
    LOST = ("VPN_PROTECTION_LOST_HEAD", "VPN_PROTECTION_LOST_HEAD_RENEGOTIATING",
            "VPN_PROTECTION_LOST", "VPN_PROTECTION_LOST_SAE",
            "VPN_PROTECTION_LOST_UNKNOWN")
    TUNNEL_WORD = {"ko": "터널", "en": "tunnel"}
    # 재협상 머리말은 세 축 자리 모두 "터널" 이라고 적지 않는다 — 공급자가 보고하는
    # 것은 connecting 이라는 상태뿐이다.
    RENEGOTIATION = ("VPN_RENEGOTIATING", "VPN_RENEGOTIATING_NO_LINK",
                     "VPN_PROTECTION_LOST_HEAD_RENEGOTIATING")
    PROTECT_WORD = {"ko": "보호", "en": "protect"}

    def test_neither_catalogue_asserts_traffic_left_the_tunnel(self):
        for lang, banned in self.FORBIDDEN.items():
            for name in self.NAMES:
                text = messages.get(name, lang)
                for phrase in banned:
                    self.assertNotIn(phrase, text, "%s/%s" % (lang, name))

    def test_the_exposure_clause_survives(self):
        """흐름 단정을 지우면서 노출 서술까지 지우지는 않는다."""
        for lang in ("ko", "en"):
            self.assertIn("L2", messages.get("VPN_PROTECTION_LOST", lang))
            self.assertIn("L2", messages.get("VPN_TUNNEL_OFF", lang))
            self.assertIn("WPA3-SAE", messages.get("VPN_PROTECTION_LOST_SAE", lang))

    def test_protection_loss_does_not_claim_a_tunnel_state_it_never_read(self):
        for lang, word in self.TUNNEL_WORD.items():
            for name in self.LOST:
                self.assertNotIn(word, messages.get(name, lang).lower(),
                                 "%s/%s" % (lang, name))

    def test_no_renegotiation_head_says_tunnel(self):
        for lang, word in self.TUNNEL_WORD.items():
            for name in self.RENEGOTIATION:
                self.assertNotIn(word, messages.get(name, lang).lower(),
                                 "%s/%s" % (lang, name))

    def test_an_sae_drop_joins_the_head_and_the_sae_body(self):
        prev = obs(vpn=vpn_state("connected"), security="WPA3_SAE")
        cur = obs(vpn=vpn_state("disconnected"), security="WPA3_SAE")
        f = by_kind(judge(prev, cur), "VPN_PROTECTION_LOST")
        self.assertEqual(f.summary, "%s %s" % (msg.VPN_PROTECTION_LOST_HEAD % "warp",
                                               msg.VPN_PROTECTION_LOST_SAE))

    def test_tunnel_off_does_not_deny_the_provider_protects_anything(self):
        for lang, word in self.PROTECT_WORD.items():
            self.assertNotIn(word, messages.get("VPN_TUNNEL_OFF", lang).lower(), lang)

    def test_a_real_drop_still_reports_the_catalogue_sentence(self):
        prev = obs(vpn=vpn_state("connected"), security="NONE")
        cur = obs(vpn=vpn_state("disconnected"), security="NONE")
        f = by_kind(judge(prev, cur), "VPN_PROTECTION_LOST")
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, "medium")
        # 활성 언어가 무엇이든 카탈로그의 그 문구가 그대로 나간다. 그 문구가
        # 무엇을 말해도 되는지는 위 검사들이 언어를 고정해 본다.
        self.assertEqual(f.summary, "%s %s" % (msg.VPN_PROTECTION_LOST_HEAD % "warp",
                                               msg.VPN_PROTECTION_LOST))
        self.assertTrue(f.evidence["passively_readable"])

    def test_the_evidence_carries_no_traffic_or_route_value(self):
        """단정을 지운 근거 — 두 판정이 읽는 관측에 트래픽·경로가 없다."""
        prev = obs(vpn=vpn_state("connected"), security="NONE")
        cur = obs(vpn=vpn_state("disconnected"), security="NONE")
        f = by_kind(judge(prev, cur), "VPN_PROTECTION_LOST")
        self.assertEqual(set(f.evidence), {"provider", "wifi_security",
                                           "security_kind", "passively_readable",
                                           "user_action"})
        prev = obs(vpn=vpn_state(mode="WarpWithDnsOverHttps", tunnel=True),
                   security="WPA2_PSK")
        cur = obs(ts="2026-01-01T00:00:05Z",
                  vpn=vpn_state(mode="DnsOverTls", tunnel=False), security="WPA2_PSK")
        f = by_kind(judge(prev, cur), "VPN_TUNNEL_OFF")
        self.assertIsNotNone(f)
        self.assertEqual(set(f.evidence), {"provider", "mode", "wifi_security",
                                           "security_kind", "passively_readable"})

if __name__ == "__main__":
    unittest.main()
