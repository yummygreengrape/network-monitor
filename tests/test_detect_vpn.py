"""VPN 판정 — 상태 전환과 끊김.

원본 스크립트는 끊김 원인을 하나만 골랐다. 여기서는 한 번의 끊김이 품질과
보안 두 축에 따로 기록되고, "왜"는 분류가 아니라 근거로 붙는다.
"""
from __future__ import annotations

import unittest

from netmon import messages
from netmon import messages as msg
from netmon import vpn as vpnmod
from netmon.collect.link import merge_probes, parse_ping
from netmon.detect import Context, attributions_for, network_key, run_all
from netmon.detect import vpn as vpn_rules
from tests.helpers import GW_MAC, by_kind, kinds, obs, vpn_state

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

    def test_the_method_labels_match_the_quality_detector(self):
        """같은 기계의 같은 주기를 두 판정이 다른 말로 부르지 않는다."""
        from netmon.detect.quality import METHOD_LABEL
        self.assertEqual(
            {k: messages.get(v, "ko") for k, v in
             {"arp": "METHOD_ARP", "icmp": "METHOD_ICMP",
              "link": "METHOD_LINK"}.items()},
            METHOD_LABEL)

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


if __name__ == "__main__":
    unittest.main()
