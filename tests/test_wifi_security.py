"""Wi-Fi 암호화 방식을 "누가 무엇을 볼 수 있는가" 로 나누는 부분.

rank() 는 강도 순서를 매기고, 여기는 노출의 의미를 가른다. 둘은 다르다 —
WPA3-SAE 는 WPA2 보다 강하지만, "비밀번호를 아는 사람이 같은 L2 에
들어온다" 는 점은 같고 "남의 트래픽을 수동으로 읽는다" 는 점은 다르다.
"""
from __future__ import annotations

import unittest

from netmon import messages as msg
from netmon import wifi_security as ws
from netmon.detect import Context, run_all
from netmon.report import exposure_notes
from tests.helpers import by_kind, kinds, obs, vpn_state


class TestClassify(unittest.TestCase):
    def test_table(self):
        for value, expect in (
            ("NONE", ws.OPEN),
            ("none", ws.OPEN),
            ("Open", ws.OPEN),
            ("WEP", ws.SHARED_PASSIVE),
            ("WPA_PSK", ws.SHARED_PASSIVE),
            ("WPA2_PSK", ws.SHARED_PASSIVE),
            ("WPA2 Personal", ws.SHARED_PASSIVE),
            ("WPA2", ws.SHARED_PASSIVE),
            ("WPA3_SAE", ws.SHARED_SAE),
            ("WPA3 Personal", ws.SHARED_SAE),
            ("WPA2/WPA3 Personal", ws.SHARED_PASSIVE),
            ("WPA2 Enterprise", ws.PER_USER),
            ("WPA3 Enterprise", ws.PER_USER),
            ("802.1X WEP", ws.PER_USER),
            ("", ws.UNKNOWN),
            (None, ws.UNKNOWN),
            ("unknown", ws.UNKNOWN),
            ("ZZZ", ws.UNKNOWN),
        ):
            with self.subTest(value=value):
                self.assertEqual(ws.classify(value), expect)

    def test_mixed_mode_counts_as_the_weaker_half(self):
        # WPA2 로도 붙을 수 있으면 WPA2 로 붙은 기기의 트래픽은 수동으로 읽힌다.
        self.assertEqual(ws.classify("WPA2/WPA3 Personal"), ws.SHARED_PASSIVE)
        self.assertTrue(ws.passively_readable("WPA2/WPA3 Personal"))

    def test_passive_reading_is_the_dividing_line(self):
        self.assertTrue(ws.passively_readable("NONE"))
        self.assertTrue(ws.passively_readable("WPA2_PSK"))
        self.assertFalse(ws.passively_readable("WPA3_SAE"))
        self.assertFalse(ws.passively_readable("WPA2 Enterprise"))
        self.assertFalse(ws.passively_readable(None))

    def test_joinable_is_unknown_when_security_is_unknown(self):
        self.assertIsNone(ws.joinable_by_others(None))
        self.assertTrue(ws.joinable_by_others("WPA3_SAE"))
        self.assertFalse(ws.joinable_by_others("WPA2 Enterprise"))


def _sample(security, applicable=True):
    return {"data": {"wifi": {"applicable": applicable,
                              "security": security,
                              "location": "granted"}}}


class TestExposureNotes(unittest.TestCase):
    def test_sae_does_not_claim_passive_decryption(self):
        note = exposure_notes(_sample("WPA3_SAE"))[0]
        self.assertEqual(note, msg.EXPOSURE_SHARED_SAE % "WPA3_SAE")
        self.assertNotIn(note, exposure_notes(_sample("WPA2_PSK")))

    def test_psk_keeps_the_passive_wording(self):
        self.assertEqual(exposure_notes(_sample("WPA2_PSK"))[0],
                         msg.EXPOSURE_SHARED_PSK % "WPA2_PSK")

    def test_open_and_enterprise_unchanged(self):
        self.assertEqual(exposure_notes(_sample("NONE"))[0], msg.EXPOSURE_OPEN)
        self.assertEqual(exposure_notes(_sample("WPA2 Enterprise")), [])

    def test_unknown_security_is_not_called_open(self):
        # 못 읽은 것을 "개방형" 이라고 적으면 없는 사실을 만드는 것이다.
        self.assertEqual(exposure_notes(_sample("")), [])
        self.assertEqual(exposure_notes(_sample(None)), [])

    def test_wired_says_nothing_about_wifi(self):
        self.assertEqual(exposure_notes(_sample("WPA2_PSK", applicable=False)), [])


class TestVpnDropWording(unittest.TestCase):
    def _drop(self, security):
        prev = obs(vpn=vpn_state("connected"), security=security)
        cur = obs(vpn=vpn_state("disconnected"), security=security)
        found = run_all(prev, cur, Context())
        return by_kind(found, "VPN_PROTECTION_LOST")

    def test_sae_drop_says_active_interception_only(self):
        f = self._drop("WPA3_SAE")
        self.assertIsNotNone(f)
        self.assertIn("SAE", f.summary)
        self.assertEqual(f.evidence["security_kind"], "shared_sae")
        self.assertIs(f.evidence["passively_readable"], False)

    def test_psk_drop_still_warns_about_reading(self):
        f = self._drop("WPA2_PSK")
        self.assertEqual(f.summary, msg.VPN_PROTECTION_LOST % f.evidence["provider"])
        self.assertIs(f.evidence["passively_readable"], True)

    def test_sae_drop_is_lower_severity_than_psk_drop(self):
        # 수동으로 읽히지 않는다는 차이가 등급에도 반영돼야 한다.
        self.assertLess(self._drop("WPA3_SAE").severity,
                        self._drop("WPA2_PSK").severity)

    def test_enterprise_drop_still_silent(self):
        self.assertNotIn("VPN_PROTECTION_LOST",
                         kinds(run_all(obs(vpn=vpn_state("connected"),
                                           security="WPA2 Enterprise"),
                                       obs(vpn=vpn_state("disconnected"),
                                           security="WPA2 Enterprise"),
                                       Context())))

    def test_unknown_security_drop_says_it_does_not_know(self):
        f = self._drop(None)
        self.assertEqual(f.summary, msg.VPN_PROTECTION_LOST_UNKNOWN % f.evidence["provider"])


if __name__ == "__main__":
    unittest.main()


class TestDowngradeWording(unittest.TestCase):
    """"같은 이름으로 유인" 은 이름이 같을 때만 할 수 있는 말이다.

    실측에서 이름이 다른 네트워크로 옮겼는데도 이 문구가 나왔다
    (2026-09-17 01:26, 06:29 — 같은 주기에 WIFI_NETWORK_SWITCHED 동반).
    """
    def _find(self, prev_sec, cur_sec, prev_ssid, cur_ssid):
        prev = obs(ssid=prev_ssid, bssid="00:00:5e:00:53:aa", security=prev_sec)
        cur = obs(ssid=cur_ssid, bssid="00:00:5e:00:53:bb", security=cur_sec)
        return by_kind(run_all(prev, cur, Context()), "WIFI_SECURITY_DOWNGRADE")

    def test_same_name_keeps_the_lure_wording(self):
        f = self._find("WPA2_PSK", "NONE", "ExampleNet", "ExampleNet")
        self.assertEqual(f.summary, msg.WIFI_SECURITY_DOWNGRADE % ("WPA2_PSK", "NONE"))
        self.assertIs(f.evidence["same_ssid"], True)

    def test_different_name_does_not_claim_a_lure(self):
        f = self._find("WPA2_PSK", "NONE", "ExampleNet", "ExampleNet-2")
        self.assertEqual(f.summary, msg.WIFI_SECURITY_DOWNGRADE_OTHER % ("WPA2_PSK", "NONE"))
        self.assertIs(f.evidence["same_ssid"], False)

    def test_unknown_name_says_it_cannot_tell(self):
        f = self._find("WPA2_PSK", "NONE", None, None)
        self.assertEqual(f.summary, msg.WIFI_SECURITY_DOWNGRADE_UNKNOWN % ("WPA2_PSK", "NONE"))
        self.assertIsNone(f.evidence["same_ssid"])

    def test_downgrade_is_still_raised_in_every_case(self):
        # 문구만 갈라진 것이지, 약화 사실 자체를 빠뜨리면 안 된다.
        for a, b in ((("ExampleNet",), ("ExampleNet",)),
                     (("ExampleNet",), ("ExampleNet-2",)),
                     ((None,), (None,))):
            with self.subTest(prev=a, cur=b):
                f = self._find("WPA2_PSK", "NONE", a[0], b[0])
                self.assertIsNotNone(f)
                self.assertEqual(f.evidence["known_ranks"][1], 0)

    def test_upgrade_is_not_called_a_downgrade(self):
        self.assertIsNone(self._find("WPA2_PSK", "WPA3_SAE", "ExampleNet", "ExampleNet"))

    def test_ap_change_without_a_readable_name_is_not_called_a_move(self):
        prev = obs(ssid=None, bssid="00:00:5e:00:53:aa")
        cur = obs(ssid=None, bssid="00:00:5e:00:53:bb")
        found = run_all(prev, cur, Context())
        self.assertIsNone(by_kind(found, "WIFI_NETWORK_SWITCHED"))
        self.assertEqual(by_kind(found, "WIFI_AP_CHANGED").summary,
                         msg.WIFI_AP_CHANGED_NAME_UNKNOWN)
