"""조사 — 유의미한 신호를 이어서 보고, 알게 된 것에 따라 기준을 고친다.

전부 합성 관측 열이다. 실제 네트워크에서 공격을 재현하지 않는다.
"""
from __future__ import annotations

import unittest

from netmon import investigate
from netmon import messages as msg
from netmon.detect import Context, attributions_for, network_key, run_all
from netmon.investigate import triggers
from netmon.investigate.model import ABANDONED, CONCLUDED, OPEN
from netmon.model import Finding
from tests.helpers import (BSSID, DNS1, GW_MAC, GW_MAC_ALT, by_kind, kinds,
                           obs, vpn_state)

FEATURES = {"detect.l2": True, "detect.dhcp": True, "detect.dns": True,
            "detect.route": True, "detect.wifi": True, "detect.quality": True,
            "detect.vpn": True}


class Harness:
    """관측 열을 그대로 흘려 보내며 판정과 조사를 함께 굴린다."""

    def __init__(self, conf=None):
        self.state = {"icmp_gw": True}
        self.inv = investigate.Investigator(conf or {})
        self.prev = None
        self.all = []

    def feed(self, o, elapsed=5.0):
        attrs = attributions_for(self.prev, o, elapsed, 5.0)
        ctx = Context(elapsed=elapsed, interval=5.0, features=FEATURES,
                      state=self.state, attributions=attrs, network=network_key(o))
        found = run_all(self.prev, o, ctx)
        extra, self.needs = self.inv.run(self.prev, o, ctx, found, self.state)
        found.extend(extra)
        self.prev = o
        self.all.extend(found)
        return found

    def investigations(self):
        return investigate.Investigator.load(self.state)

    def only(self, kind):
        return [i for i in self.investigations() if i.kind == kind]

    def closed(self, kind):
        return [i for i in self.investigations() if i.kind == kind and not i.open]

    def opened(self, kind):
        return [i for i in self.investigations() if i.kind == kind and i.open]


def ts(n):
    return "2026-01-01T00:%02d:%02dZ" % (n // 60, n % 60)


class TestTriggerRules(unittest.TestCase):
    def test_default_rules_pick_security_high_and_medium(self):
        r = triggers.merge_rules(None)
        high = Finding(axis="security", kind="X", confidence="confirmed",
                       severity="high", summary="")
        low = Finding(axis="security", kind="X", confidence="confirmed",
                      severity="low", summary="")
        self.assertTrue(triggers.is_meaningful(high, r))
        self.assertFalse(triggers.is_meaningful(low, r))

    def test_attributed_findings_do_not_open_investigations(self):
        """장소를 옮길 때마다 조사가 쏟아지면 쓸모가 없다."""
        r = triggers.merge_rules(None)
        f = Finding(axis="security", kind="X", confidence="confirmed",
                    severity="high", summary="", attribution="network_change")
        self.assertFalse(triggers.is_meaningful(f, r))
        r2 = triggers.merge_rules({"include_attributed": True})
        self.assertTrue(triggers.is_meaningful(f, r2))

    def test_never_list_wins_over_kinds(self):
        r = triggers.merge_rules({"kinds": ["MEASUREMENT_GAP"]})
        f = Finding(axis="info", kind="MEASUREMENT_GAP", confidence="confirmed",
                    severity="info", summary="")
        self.assertFalse(triggers.is_meaningful(f, r))

    def test_user_can_widen_the_criterion(self):
        r = triggers.merge_rules({"severities": ["high", "medium", "low"]})
        f = Finding(axis="security", kind="X", confidence="confirmed",
                    severity="low", summary="")
        self.assertTrue(triggers.is_meaningful(f, r))


class TestL2Investigation(unittest.TestCase):
    def test_mac_change_opens_an_investigation(self):
        h = Harness()
        h.feed(obs(ts=ts(0), gw_mac=GW_MAC))
        f = h.feed(obs(ts=ts(5), gw_mac=GW_MAC_ALT))
        self.assertIn("INVESTIGATION_OPENED", kinds(f))
        invs = h.only("l2_identity")
        self.assertEqual(len(invs), 1)
        self.assertEqual(invs[0].trigger, "GW_MAC_CHANGED")
        self.assertTrue(invs[0].open)

    def test_stable_new_mac_concludes_as_probably_an_ap_swap(self):
        h = Harness()
        h.feed(obs(ts=ts(0), gw_mac=GW_MAC))
        h.feed(obs(ts=ts(5), gw_mac=GW_MAC_ALT))
        for i in range(22):
            h.feed(obs(ts=ts(10 + i * 5), gw_mac=GW_MAC_ALT))
        inv = h.closed("l2_identity")[0]
        self.assertEqual(inv.status, CONCLUDED)
        self.assertEqual(inv.verdict, msg.INV_L2_STABLE_VERDICT)
        self.assertEqual(inv.confidence, "possible")
        c = by_kind(h.all, "INVESTIGATION_CONCLUDED")
        self.assertIn(msg.INV_L2_STABLE % inv.criteria["stable_for"], c.summary)

    def test_flapping_mac_concludes_as_suspicious(self):
        """정상적인 접속점 교체는 되돌아가지 않는다."""
        h = Harness()
        h.feed(obs(ts=ts(0), gw_mac=GW_MAC))
        for i, mac in enumerate([GW_MAC_ALT, GW_MAC, GW_MAC_ALT], start=1):
            h.feed(obs(ts=ts(i * 5), gw_mac=mac))
        inv = h.closed("l2_identity")[0]
        self.assertEqual(inv.status, CONCLUDED)
        self.assertEqual(inv.verdict, msg.INV_L2_FLAPPING_VERDICT)
        self.assertEqual(inv.confidence, "suspect")

    def test_corroborating_signal_widens_criteria_then_escalates(self):
        """MAC 변경에 DHCP 변조가 겹치면 기준을 넓히고 결론을 올린다."""
        h = Harness()
        h.feed(obs(ts=ts(0), gw_mac=GW_MAC))
        h.feed(obs(ts=ts(5), gw_mac=GW_MAC_ALT))
        inv_before = h.only("l2_identity")[0]
        self.assertNotIn("DNS_LOCAL_PROXY_CHANGED", inv_before.criteria["watch_kinds"])

        f = h.feed(obs(ts=ts(10), gw_mac=GW_MAC_ALT, dhcp_server="192.0.2.99"))
        self.assertIn("INVESTIGATION_RETUNED", kinds(f))
        inv = h.closed("l2_identity")[0]
        self.assertEqual(inv.status, CONCLUDED)
        self.assertEqual(inv.confidence, "suspect")
        c = by_kind(f, "INVESTIGATION_CONCLUDED")
        self.assertEqual(c.axis, "security")
        self.assertEqual(c.severity, "high")
        self.assertIn("DHCP_SERVER_CHANGED", c.summary)

    def test_criteria_change_is_recorded_with_before_and_after(self):
        h = Harness()
        h.feed(obs(ts=ts(0), gw_mac=GW_MAC))
        h.feed(obs(ts=ts(5), gw_mac=GW_MAC_ALT))
        h.feed(obs(ts=ts(10), gw_mac=GW_MAC_ALT, dhcp_server="192.0.2.99"))
        inv = h.closed("l2_identity")[0]
        tuned = [e for e in inv.evidence if e["what"] == msg.INV_NOTE_RETUNE]
        self.assertTrue(tuned, "기준을 바꿨으면 기록이 있어야 한다")
        self.assertIn("reason", tuned[0])
        self.assertIn("before", tuned[0])
        self.assertIn("after", tuned[0])


class TestVpnInvestigation(unittest.TestCase):
    def _drop_cycle(self, h, n, first_hop_ok=True):
        h.feed(obs(ts=ts(n), vpn=vpn_state("connected"), icmp_ok=first_hop_ok))
        return h.feed(obs(ts=ts(n + 5), vpn=vpn_state("disconnected"),
                          icmp_ok=first_hop_ok))

    def test_repeated_drops_widen_criteria_to_include_link_quality(self):
        h = Harness()
        self._drop_cycle(h, 0)
        f = self._drop_cycle(h, 10)
        self.assertIn("INVESTIGATION_RETUNED", kinds(f))
        inv = h.only("vpn_drop")[0]
        self.assertTrue(inv.criteria.get("watch_link"))
        self.assertIn("FIRST_HOP_UNREACHABLE", inv.criteria["watch_kinds"])

    def test_three_drops_with_healthy_link_blames_the_tunnel(self):
        h = Harness()
        self._drop_cycle(h, 0)
        self._drop_cycle(h, 10)
        self._drop_cycle(h, 20)
        done = h.closed("vpn_drop")
        self.assertEqual(len(done), 1)
        self.assertEqual(done[0].status, CONCLUDED)
        self.assertEqual(done[0].verdict, msg.INV_VPN_VERDICT_TUNNEL)
        self.assertEqual(h.opened("vpn_drop"), [],
                         "결론을 낸 주기에 같은 조사가 또 열리면 안 된다")

    def test_single_drop_does_not_conclude_yet(self):
        h = Harness()
        self._drop_cycle(h, 0)
        self.assertTrue(h.only("vpn_drop")[0].open)

    def test_a_connecting_transition_opens_the_same_investigation(self):
        """재협상(`connecting`)으로 바뀐 전환도 종전처럼 조사를 연다.

        요약문만 "재협상 중" 으로 바뀌었고 판정 종류는 그대로라서, 조사를
        여는 기준(`triggers.DEFAULT_RULES` 의 VPN_DISCONNECTED)도 그대로다.
        이 픽스처들이 `disconnected` 만 써서 이 경로를 지나지 않았다.
        """
        h = Harness()
        h.feed(obs(ts=ts(0), vpn=vpn_state("connected"), icmp_ok=True))
        f = h.feed(obs(ts=ts(5), vpn=vpn_state("connecting"), icmp_ok=True))
        self.assertIn("INVESTIGATION_OPENED", kinds(f))
        self.assertEqual(len(h.opened("vpn_drop")), 1)
        self.assertIn("재협상", by_kind(f, "VPN_DISCONNECTED").summary)

    def test_a_connecting_drop_counts_like_any_other(self):
        """세 번 끊기면 상태가 `connecting` 이어도 같은 결론에 닿는다."""
        h = Harness()
        for n in (0, 10, 20):
            h.feed(obs(ts=ts(n), vpn=vpn_state("connected"), icmp_ok=True))
            h.feed(obs(ts=ts(n + 5), vpn=vpn_state("connecting"), icmp_ok=True))
        done = h.closed("vpn_drop")
        self.assertEqual(len(done), 1)
        self.assertEqual(done[0].status, CONCLUDED)


class TestPathConfigInvestigation(unittest.TestCase):
    def test_persisting_change_concludes_confirmed(self):
        """존속 기준은 주기가 아니라 시간이다 (기본 300초).

        조사 중에는 측정 간격을 줄이므로 주기 수는 실제 경과 시간과 무관해진다.
        실측에서 12주기(36초)만에 "자리 잡았다"고 끝내고 12초 뒤 원복됐다.
        """
        h = Harness()
        h.feed(obs(ts=ts(0), resolvers=(DNS1,)))
        h.feed(obs(ts=ts(5), resolvers=("192.0.2.66",)))
        for i in range(70):          # 5초 간격 × 70 = 350초 > 300초
            h.feed(obs(ts=ts(10 + i * 5), resolvers=("192.0.2.66",)))
        inv = h.closed("path_config")[0]
        self.assertEqual(inv.status, CONCLUDED)
        self.assertEqual(inv.confidence, "confirmed")

    def test_a_short_lived_change_does_not_conclude(self):
        """WARP 가 49초 끊긴 동안의 리졸버 변화로 결론을 내면 안 된다."""
        h = Harness()
        h.feed(obs(ts=ts(0), resolvers=(DNS1,)))
        h.feed(obs(ts=ts(5), resolvers=("192.0.2.66",)))
        for i in range(9):           # 45초
            h.feed(obs(ts=ts(10 + i * 5), resolvers=("192.0.2.66",)))
        self.assertEqual(h.closed("path_config"), [])
        self.assertEqual(len(h.opened("path_config")), 1)

    def test_repeated_flipping_retunes_to_contested(self):
        h = Harness()
        h.feed(obs(ts=ts(0), resolvers=(DNS1,)))
        h.feed(obs(ts=ts(5), resolvers=("192.0.2.66",)))
        h.feed(obs(ts=ts(10), resolvers=(DNS1,)))
        f = h.feed(obs(ts=ts(15), resolvers=("192.0.2.66",)))
        inv = h.opened("path_config")[0]
        self.assertTrue(inv.criteria.get("contested"))
        self.assertIn("INVESTIGATION_RETUNED", kinds(f))


class TestLifecycle(unittest.TestCase):
    def test_network_change_abandons_and_says_so(self):
        h = Harness()
        h.feed(obs(ts=ts(0), gw_mac=GW_MAC))
        h.feed(obs(ts=ts(5), gw_mac=GW_MAC_ALT))
        f = h.feed(obs(ts=ts(10), gw_mac=GW_MAC_ALT, my_ip="198.51.100.50"))
        self.assertIn("INVESTIGATION_ABANDONED", kinds(f))
        self.assertEqual(h.closed("l2_identity")[0].status, ABANDONED)

    def test_budget_closes_an_investigation_that_cannot_decide(self):
        h = Harness()
        h.feed(obs(ts=ts(0), gw_mac=GW_MAC))
        h.feed(obs(ts=ts(5), vpn=vpn_state("connected")))
        h.feed(obs(ts=ts(10), vpn=vpn_state("disconnected")))
        for i in range(125):
            h.feed(obs(ts=ts(20 + i * 5), vpn=vpn_state("disconnected")))
            if not h.only("vpn_drop")[0].open:
                break
        done = h.closed("vpn_drop")
        self.assertTrue(done)
        self.assertIn("%d" % done[0].cycles, done[0].verdict)

    def test_state_survives_a_round_trip(self):
        """에이전트를 재시작해도 조사가 이어져야 한다."""
        import json
        h = Harness()
        h.feed(obs(ts=ts(0), gw_mac=GW_MAC))
        h.feed(obs(ts=ts(5), gw_mac=GW_MAC_ALT))
        revived = json.loads(json.dumps(h.state))
        invs = investigate.Investigator.load(revived)
        self.assertEqual(len(invs), 1)
        self.assertTrue(invs[0].open)
        self.assertEqual(invs[0].criteria["baseline_mac"], GW_MAC_ALT)

    def test_max_open_is_respected(self):
        h = Harness({"max_open": 1})
        h.feed(obs(ts=ts(0), gw_mac=GW_MAC, resolvers=(DNS1,)))
        h.feed(obs(ts=ts(5), gw_mac=GW_MAC_ALT, resolvers=("192.0.2.66",)))
        self.assertEqual(len([i for i in h.investigations() if i.open]), 1)

    def test_disabled_investigator_does_nothing(self):
        h = Harness({"enabled": False})
        h.feed(obs(ts=ts(0), gw_mac=GW_MAC))
        f = h.feed(obs(ts=ts(5), gw_mac=GW_MAC_ALT))
        self.assertNotIn("INVESTIGATION_OPENED", kinds(f))
        self.assertEqual(h.investigations(), [])

    def test_cooldown_prevents_immediate_reopening_and_says_so(self):
        h = Harness({"cooldown_cycles": 10})
        last = []
        for st, n in [("connected", 0), ("disconnected", 5), ("connected", 10),
                      ("disconnected", 15), ("connected", 20), ("disconnected", 25)]:
            last = h.feed(obs(ts=ts(n), vpn=vpn_state(st), icmp_ok=True))

        # 결론을 낸 바로 그 주기에, 같은 신호로 다시 열리지 않는다
        self.assertIn("INVESTIGATION_CONCLUDED", kinds(last))
        self.assertIn("INVESTIGATION_COOLDOWN", kinds(last),
                      "안 연 이유가 기록에 남아야 한다")
        self.assertEqual(h.opened("vpn_drop"), [])

        # 냉각 중에는 같은 안내를 되풀이하지 않는다
        h.feed(obs(ts=ts(30), vpn=vpn_state("connected"), icmp_ok=True))
        f = h.feed(obs(ts=ts(35), vpn=vpn_state("disconnected"), icmp_ok=True))
        self.assertNotIn("INVESTIGATION_COOLDOWN", kinds(f))
        self.assertEqual(h.opened("vpn_drop"), [])

    def test_cooldown_expires_and_investigation_can_reopen(self):
        h = Harness({"cooldown_cycles": 3})
        for st, n in [("connected", 0), ("disconnected", 5), ("connected", 10),
                      ("disconnected", 15), ("connected", 20), ("disconnected", 25)]:
            h.feed(obs(ts=ts(n), vpn=vpn_state(st), icmp_ok=True))
        self.assertEqual(h.opened("vpn_drop"), [])
        for i in range(4):
            h.feed(obs(ts=ts(30 + i * 5), vpn=vpn_state("disconnected"), icmp_ok=True))
        h.feed(obs(ts=ts(60), vpn=vpn_state("connected"), icmp_ok=True))
        h.feed(obs(ts=ts(65), vpn=vpn_state("disconnected"), icmp_ok=True))
        self.assertEqual(len(h.opened("vpn_drop")), 1,
                         "냉각이 끝나면 같은 문제를 다시 조사한다")

    def test_open_investigation_asks_for_faster_sampling(self):
        h = Harness()
        h.feed(obs(ts=ts(0), gw_mac=GW_MAC))
        h.feed(obs(ts=ts(5), gw_mac=GW_MAC_ALT))
        self.assertEqual(h.needs.get("interval"), 2)
        self.assertEqual(h.needs.get("open"), 1)


if __name__ == "__main__":
    unittest.main()
