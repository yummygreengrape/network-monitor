"""문구 카탈로그.

문구가 여러 파일에 흩어져 있으면 어투를 고칠 때마다 빠뜨리는 것이 생긴다.
전부 netmon/messages/<코드>.py 에 모으고, 여기서 다음을 지킨다.

  - 두 언어의 이름과 자리표시자가 정확히 같다
  - 판정 요약문이 정해진 어투를 벗어나지 않는다
  - 모든 문구가 실제로 한 번씩 만들어진다 (자리표시자 개수 확인)
"""
from __future__ import annotations

import re
import unittest

from netmon import messages
from netmon.detect import Context, attributions_for, network_key, run_all
from tests.helpers import (BSSID, BSSID_ALT, DNS1, GW_MAC, GW_MAC_ALT, SSID,
                           obs, vpn_state)

SPEC = re.compile(r"%[-#0 +]*[\d.*]*[a-zA-Z%]")

# 판정 요약문은 명사형으로 끝낸다. 물음표로 끝나는 질문은 대상이 아니다.
KO_SENTENCE_ENDINGS = ("습니다", "합니다", "입니다", "됩니다", "했다", "이다", "한다")


def ko_finding_keys():
    return [k for k in messages.keys("ko")
            if not k.startswith(("WZ_", "CLI_", "WATCH_", "REPORT_", "CONF_"))]


class TestCataloguesAgree(unittest.TestCase):
    def test_same_names(self):
        self.assertEqual(set(messages.keys("ko")), set(messages.keys("en")))

    def test_same_placeholders(self):
        for key in messages.keys("ko"):
            self.assertEqual(SPEC.findall(messages.get(key, "ko")),
                             SPEC.findall(messages.get(key, "en")),
                             "%s 의 자리표시자가 두 언어에서 다르다" % key)

    def test_no_empty_messages(self):
        for code in messages.available():
            for key in messages.keys(code):
                self.assertTrue(messages.get(key, code).strip(),
                                "%s/%s 가 비어 있다" % (code, key))


class TestTone(unittest.TestCase):
    def test_korean_findings_end_in_noun_form(self):
        """"~했습니다" 가 아니라 "~됨" 으로 끝낸다. 사용자가 고른 어투다."""
        bad = []
        for key in ko_finding_keys():
            text = messages.get(key, "ko").rstrip()
            if not text.endswith((".", "?", ":")):
                continue
            body = text.rstrip(".?:").rstrip()
            if body.endswith(KO_SENTENCE_ENDINGS):
                bad.append(key)
        self.assertEqual(bad, [], "서술형으로 끝나는 판정 문구: %s" % bad)

    def test_english_findings_do_not_address_the_reader(self):
        """영어 문구에서 1·2인칭을 쓰지 않는다. 기록은 보고이지 대화가 아니다."""
        bad = []
        for key in ko_finding_keys():
            words = re.findall(r"\b\w+\b", messages.get(key, "en").lower())
            if {"you", "your", "we", "our", "i"} & set(words):
                bad.append(key)
        self.assertEqual(bad, [])


class TestEveryMessageRenders(unittest.TestCase):
    def test_all_findings_render_in_both_languages(self):
        cases = [
            dict(gw_mac=GW_MAC_ALT), dict(duplicate_ip=3),
            dict(dhcp_server="192.0.2.99"), dict(dns=("192.0.2.66",)),
            dict(resolvers=("192.0.2.66",)),
            dict(proxy={"ProxyAutoDiscoveryEnable": "1"}),
            dict(default6=(("2001:db8::1", "en0"),)), dict(security="NONE"),
            dict(ssid=SSID, bssid=BSSID_ALT, gw_mac=GW_MAC_ALT),
            dict(link_active="FALSE"), dict(icmp_ok=False, gw_mac=None),
            dict(rtt=500.0), dict(vpn=vpn_state("disconnected")),
            dict(vpn=vpn_state("unknown")),
            dict(shared_macs={"00:00:5e:00:53:07":
                              [{"id": "ipv4", "v": "192.0.2.%d" % i} for i in range(4)]}),
        ]
        features = {k: True for k in ("detect.l2", "detect.dhcp", "detect.dns",
                                      "detect.route", "detect.wifi", "detect.quality",
                                      "detect.vpn", "detect.evil_twin")}
        seen = set()
        for code in messages.available():
            messages.set_language(code)
            try:
                for case in cases:
                    base = dict(ssid=SSID, bssid=BSSID, vpn=vpn_state("connected"))
                    prev = obs(ts="2026-01-01T00:00:00Z", **base)
                    cur = obs(ts="2026-01-01T00:00:05Z", **dict(base, **case))
                    ctx = Context(elapsed=5.0, interval=5.0, features=features,
                                  state={"icmp_gw": True, "rtt_ewma": 5.0,
                                         "arp_reply_rate": 3.0, "gw_fail_streak": 2},
                                  attributions=attributions_for(prev, cur, 5.0, 5.0),
                                  network=network_key(cur))
                    for f in run_all(prev, cur, ctx):
                        self.assertNotEqual(f.kind, "DETECTOR_ERROR", f.summary)
                        self.assertTrue(f.summary.strip())
                        seen.add(f.kind)
            finally:
                messages.set_language("ko")
        self.assertGreater(len(seen), 12, "판정 종류가 너무 적게 생성됐다: %s" % sorted(seen))


class TestLanguageSelection(unittest.TestCase):
    def tearDown(self):
        messages.set_language("ko")

    def test_default_is_korean(self):
        self.assertEqual(messages.set_language(None), "ko")

    def test_unknown_code_falls_back(self):
        self.assertEqual(messages.set_language("fr"), "ko")

    def test_env_beats_config(self):
        import os
        os.environ[messages.ENV] = "en"
        try:
            self.assertEqual(messages.resolve("ko"), "en")
        finally:
            del os.environ[messages.ENV]
        self.assertEqual(messages.resolve("ko"), "ko")

    def test_lookup_follows_the_active_language(self):
        messages.set_language("en")
        self.assertEqual(messages.DEFAULT_ROUTE_CHANGED, messages.get("DEFAULT_ROUTE_CHANGED", "en"))
        messages.set_language("ko")
        self.assertEqual(messages.DEFAULT_ROUTE_CHANGED, messages.get("DEFAULT_ROUTE_CHANGED", "ko"))

    def test_unknown_name_raises_instead_of_returning_blank(self):
        """조용히 빈 문자열을 주면 화면에서 문구가 사라진 것을 알아채기 어렵다."""
        with self.assertRaises(AttributeError):
            messages.NOT_A_REAL_MESSAGE


if __name__ == "__main__":
    unittest.main()


class TestSummariesNeverEmbedIdentifiers(unittest.TestCase):
    """판정 요약문에 식별자를 넣지 않는다.

    보고서와 실시간 화면은 요약문만 출력한다(근거는 기록에만 남는다). 요약문이
    식별자를 담지 않는 덕에 **가리지 않은 보고서도 그대로 공유할 수 있다.**
    실데이터로 확인한 성질이고, 문구를 고치다 깨지기 쉬우므로 여기서 지킨다.
    """

    SECRETS = ("192.0.2.", "198.51.100.", "2001:db8:", "00:00:5e:00:53:",
               "ExampleNet")

    def test_no_summary_contains_a_synthetic_identifier(self):
        from netmon.detect import (Context, attributions_for, network_key,
                                   run_all)
        from tests.helpers import (BSSID, BSSID_ALT, GW_MAC, GW_MAC_ALT, SSID,
                                   obs, vpn_state)
        cases = [
            dict(gw_mac=GW_MAC_ALT), dict(duplicate_ip=3),
            dict(dhcp_server="192.0.2.99"), dict(dns=("192.0.2.66",)),
            dict(resolvers=("192.0.2.66",)),
            dict(proxy={"ProxyAutoDiscoveryEnable": "1"}),
            dict(default6=(("2001:db8::1", "en0"),)), dict(security="NONE"),
            dict(ssid=SSID, bssid=BSSID_ALT, gw_mac=GW_MAC_ALT),
            dict(icmp_ok=False, gw_mac=None), dict(rtt=500.0),
            dict(vpn=vpn_state("disconnected")),
            dict(shared_macs={"00:00:5e:00:53:07":
                              {"count": 5,
                               "addresses": [{"id": "ipv4", "v": "192.0.2.%d" % i}
                                             for i in range(5)]}}),
        ]
        features = {k: True for k in ("detect.l2", "detect.dhcp", "detect.dns",
                                      "detect.route", "detect.wifi", "detect.quality",
                                      "detect.vpn", "detect.evil_twin")}
        offenders = []
        for code in messages.available():
            messages.set_language(code)
            try:
                for case in cases:
                    base = dict(ssid=SSID, bssid=BSSID, vpn=vpn_state("connected"))
                    prev = obs(ts="2026-01-01T00:00:00Z", **base)
                    cur = obs(ts="2026-01-01T00:00:05Z", **dict(base, **case))
                    ctx = Context(elapsed=5.0, interval=5.0, features=features,
                                  state={"icmp_gw": True, "rtt_ewma": 5.0,
                                         "arp_reply_rate": 0.8, "gw_fail_streak": 2},
                                  attributions=attributions_for(prev, cur, 5.0, 5.0),
                                  network=network_key(cur))
                    for f in run_all(prev, cur, ctx):
                        for secret in self.SECRETS:
                            if secret in f.summary:
                                offenders.append((code, f.kind, secret))
            finally:
                messages.set_language("ko")
        self.assertEqual(offenders, [],
                         "요약문에 식별자가 들어갔다: %s" % offenders)

    def test_evidence_is_where_identifiers_belong(self):
        """식별자는 근거에만, 그것도 감싼 형태로 들어간다."""
        from netmon.detect import Context, network_key, run_all
        from netmon.model import ID_KINDS
        from netmon.redact import tagged_values
        from tests.helpers import GW_MAC, GW_MAC_ALT, obs

        prev = obs(ts="2026-01-01T00:00:00Z", gw_mac=GW_MAC)
        cur = obs(ts="2026-01-01T00:00:05Z", gw_mac=GW_MAC_ALT)
        ctx = Context(elapsed=5.0, interval=5.0, features={"detect.l2": True},
                      state={"icmp_gw": True}, attributions=[], network=network_key(cur))
        found = [f for f in run_all(prev, cur, ctx) if f.kind == "GW_MAC_CHANGED"]
        self.assertTrue(found)
        tagged = tagged_values(found[0].evidence)
        self.assertIn("mac", tagged)
        self.assertIn(GW_MAC_ALT, tagged["mac"])
