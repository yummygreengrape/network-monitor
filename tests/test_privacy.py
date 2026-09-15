"""식별자 가리기와 동의.

이 도구는 개인정보를 다룬다. 가리기가 깨지면 공유한 보고서에서 네트워크와
장소가 드러난다.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest

from netmon import config as configmod
from netmon import redact as redactmod
from netmon.model import ident
from tests.helpers import GW, GW_MAC, obs


class TestRedaction(unittest.TestCase):
    def setUp(self):
        self.salt = b"test-salt-not-a-real-one"

    def test_tagged_values_are_replaced(self):
        d = obs(gateway=GW, gw_mac=GW_MAC).as_dict()
        red = redactmod.redact(d, self.salt)
        text = json.dumps(red)
        self.assertNotIn(GW, text)
        self.assertNotIn(GW_MAC, text)

    def test_same_value_gives_same_token(self):
        """가린 뒤에도 '바뀌었다가 돌아왔다' 같은 관계가 보여야 한다."""
        a = redactmod.redact(ident("mac", GW_MAC), self.salt)
        b = redactmod.redact(ident("mac", GW_MAC), self.salt)
        self.assertEqual(a["v"], b["v"])

    def test_different_kinds_do_not_collide(self):
        same_text = "192.0.2.1"
        as_ip = redactmod.redact(ident("ipv4", same_text), self.salt)["v"]
        as_host = redactmod.redact(ident("hostname", same_text), self.salt)["v"]
        self.assertNotEqual(as_ip, as_host)

    def test_different_salt_gives_different_token(self):
        a = redactmod.redact(ident("mac", GW_MAC), b"salt-a")["v"]
        b = redactmod.redact(ident("mac", GW_MAC), b"salt-b")["v"]
        self.assertNotEqual(a, b)

    def test_untagged_values_are_left_alone(self):
        """감싸지 않은 값을 문자열 추측으로 가리지 않는다.

        추측해서 가리면 반쯤 가려진 로그가 조용히 만들어진다. 감싸야 할 값을
        감싸지 않은 것은 스키마 버그이고, 버그로 드러나는 편이 낫다.
        """
        d = {"note": "gateway is 192.0.2.1", "mac": ident("mac", GW_MAC)}
        red = redactmod.redact(d, self.salt)
        self.assertEqual(red["note"], "gateway is 192.0.2.1")
        self.assertNotIn(GW_MAC, json.dumps(red))

    def test_salt_file_is_owner_only(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sub", "salt")
            salt = redactmod.load_or_create_salt(path)
            self.assertTrue(salt)
            self.assertEqual(oct(os.stat(path).st_mode)[-3:], "600")
            self.assertEqual(redactmod.load_or_create_salt(path), salt,
                             "두 번째 호출은 같은 솔트를 돌려줘야 한다")


class TestConsent(unittest.TestCase):
    def _cfg(self, d):
        return configmod.load(os.path.join(d, "config.json"))

    def test_feature_is_inert_without_consent(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = self._cfg(d)
            cfg.set_feature("detect.evil_twin", True)
            self.assertTrue(cfg.feature("detect.evil_twin"))
            self.assertFalse(cfg.effective("detect.evil_twin"),
                             "켜도 동의가 없으면 동작하지 않는다")
            self.assertIn("동의 필요", cfg.blocked_reason("detect.evil_twin"))

    def test_consent_plus_feature_enables(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = self._cfg(d)
            cfg.grant("location")
            cfg.set_feature("detect.evil_twin", True)
            self.assertTrue(cfg.effective("detect.evil_twin"))

    def test_revoking_consent_also_turns_the_feature_off(self):
        """동의를 물린 뒤 기능이 켜진 채 남으면 다음 동의 때 조용히 되살아난다."""
        with tempfile.TemporaryDirectory() as d:
            cfg = self._cfg(d)
            cfg.grant("location")
            cfg.set_feature("detect.evil_twin", True)
            cfg.revoke("location")
            self.assertFalse(cfg.feature("detect.evil_twin"))
            self.assertFalse(cfg.effective("detect.evil_twin"))

    def test_external_probes_default_off(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = self._cfg(d)
            for feat in ("detect.dns_intercept", "detect.tls_intercept", "detect.public_ip"):
                self.assertFalse(cfg.feature(feat), "%s 는 기본이 꺼짐이어야 한다" % feat)
            self.assertFalse(cfg.consented("external_probes"))

    def test_vpn_monitoring_default_off(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(self._cfg(d).feature("vpn.enabled"))

    def test_config_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = self._cfg(d)
            cfg.grant("location", note="테스트")
            cfg.save()
            again = self._cfg(d)
            self.assertTrue(again.consented("location"))


class TestCollectorWithholdsIdentity(unittest.TestCase):
    def test_wifi_collector_omits_ssid_without_consent(self):
        o = obs(ssid=None, bssid=None)
        self.assertIsNone(o.get("wifi", "ssid"))
        self.assertIsNone(o.get("wifi", "bssid"))


if __name__ == "__main__":
    unittest.main()
