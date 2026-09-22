"""VPN 판정 — 상태 전환과 끊김.

원본 스크립트는 끊김 원인을 하나만 골랐다. 여기서는 한 번의 끊김이 품질과
보안 두 축에 따로 기록되고, "왜"는 분류가 아니라 근거로 붙는다.
"""
from __future__ import annotations

import unittest
from unittest import mock

from netmon import messages
from netmon import messages as msg
from netmon import vpn as vpnmod
from netmon.collect.link import merge_probes, parse_ping
from netmon.detect import Context, attributions_for, network_key, run_all
from netmon.detect import vpn as vpn_rules
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
            state["vpn_endpoint_probes"] = probes
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
        f = self._drop(error="TimeoutError")
        self.assertEqual(f.evidence["tunnel_endpoint_error"], "TimeoutError")
        self.assertFalse(f.evidence["tunnel_endpoint_reachable"])

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


if __name__ == "__main__":
    unittest.main()
