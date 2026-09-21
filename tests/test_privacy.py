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
from tests.helpers import (ENDPOINT, ENDPOINT_REASON, GW, GW_MAC,
                           endpoint_probe, obs, vpn_state)


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


class TestTunnelEndpointConsent(unittest.TestCase):
    """터널 엔드포인트 측정도 기존 동의에 묶인다 (QA-14, ADV-5, AC-13)."""

    FEATURE = "vpn.tunnel_probe"

    def _cfg(self, d):
        return configmod.load(os.path.join(d, "config.json"))

    def test_it_is_bound_to_external_probes(self):
        self.assertEqual(configmod.FEATURE_CONSENT[self.FEATURE], "external_probes")
        self.assertIn(self.FEATURE, configmod.CONSENTS["external_probes"]["enables"])

    def test_it_is_off_by_default(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = self._cfg(d)
            self.assertFalse(cfg.feature(self.FEATURE))
            self.assertFalse(cfg.effective(self.FEATURE))

    def test_the_feature_alone_is_inert(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = self._cfg(d)
            cfg.set_feature(self.FEATURE, True)
            self.assertFalse(cfg.effective(self.FEATURE))
            self.assertIn("동의 필요", cfg.blocked_reason(self.FEATURE))

    def test_the_consent_alone_is_inert(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = self._cfg(d)
            cfg.grant("external_probes")
            self.assertFalse(cfg.effective(self.FEATURE))
            self.assertEqual(cfg.blocked_reason(self.FEATURE), "꺼져 있음")

    def test_revoking_turns_it_off_too(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = self._cfg(d)
            cfg.grant("external_probes")
            cfg.set_feature(self.FEATURE, True)
            self.assertTrue(cfg.effective(self.FEATURE))
            cfg.revoke("external_probes")
            self.assertFalse(cfg.feature(self.FEATURE))
            self.assertFalse(cfg.effective(self.FEATURE))

    def test_an_existing_grant_is_not_asked_again_and_does_not_switch_it_on(self):
        """이미 동의한 사람에게 다시 묻지 않고, 저절로 켜지지도 않는다 (QA-14).

        새 기능 키를 모르는 판에서 저장된 설정을 그대로 읽는다.
        """
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "config.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"version": 1,
                           "consents": {"external_probes": {
                               "granted": True, "at": "2026-01-01T00:00:00Z",
                               "note": "초기 설정에서 선택"}},
                           "features": {"detect.public_ip": True}}, fh)
            cfg = configmod.load(path)
            self.assertTrue(cfg.consented("external_probes"))
            self.assertTrue(cfg.effective("detect.public_ip"))
            self.assertFalse(cfg.feature(self.FEATURE),
                             "동의가 있어도 새 기능이 저절로 켜지면 안 된다")
            self.assertFalse(cfg.effective(self.FEATURE))

    def test_the_consent_text_says_what_goes_out(self):
        text = configmod.CONSENTS["external_probes"]
        self.assertIn("엔드포인트", text["why"])
        self.assertIn("엔드포인트", text["sends_out"])
        # 언제 보내는지도 적는다 — 평소 주기에는 나가지 않는다.
        self.assertIn("끊", text["sends_out"])

    def test_the_setup_wizard_says_it_too(self):
        """초기 설정은 동의를 받으면 `enables` 의 기능을 함께 켠다.

        그 화면에 나오는 문구는 별도 카탈로그라(`netmon/messages`), 여기서
        같이 보지 않으면 "말하지 않고 켜는" 상태가 된다.
        """
        from netmon import messages

        self.assertIn(self.FEATURE, configmod.CONSENTS["external_probes"]["enables"])
        self.assertIn("터널", messages.get("WZ_EXTERNAL_BODY", "ko"))
        self.assertIn("끊긴", messages.get("WZ_EXTERNAL_BODY", "ko"))
        self.assertIn("tunnel endpoint", messages.get("WZ_EXTERNAL_BODY", "en"))


class TestTunnelEndpointIsWrapped(unittest.TestCase):
    """주소는 감싸서 기록하고, 사유 원문은 그대로 둔다 (QA-6, AC-5)."""

    def setUp(self):
        self.salt = b"test-salt-not-a-real-one"

    def test_the_address_becomes_a_token_when_exported(self):
        o = endpoint_probe(obs(vpn=vpn_state("disconnected", reason=ENDPOINT_REASON)))
        red = redactmod.redact(o.as_dict(), self.salt)
        link = json.dumps(red["data"]["link"], ensure_ascii=False)
        self.assertNotIn(ENDPOINT, link)
        self.assertIn("ipv4:", link)

    def test_the_provider_reason_stays_as_it_is(self):
        """로컬 기록에는 원문을 남긴다 — 이 저장소의 공개된 설계 그대로다.

        감싸지 않은 문자열은 내보낼 때도 바뀌지 않는다(redact 는 감싼 값만
        바꾼다). 그래서 사유에 적힌 주소는 내보낸 기록에도 남는다. 이 갈래를
        이 필드에서만 뒤집지 않기로 했으므로(AC-5), 그 사실을 못 박아 둔다.
        """
        o = endpoint_probe(obs(vpn=vpn_state("disconnected", reason=ENDPOINT_REASON)))
        red = redactmod.redact(o.as_dict(), self.salt)
        self.assertEqual(red["data"]["vpn"]["warp"]["reason"], ENDPOINT_REASON)

    def test_the_evidence_field_is_redactable(self):
        """끊김 증거에 실린 주소도 같은 방식으로 가려진다."""
        evidence = {"tunnel_endpoint": ident("ipv4", ENDPOINT),
                    "tunnel_endpoint_reachable": False}
        red = redactmod.redact(evidence, self.salt)
        self.assertNotIn(ENDPOINT, json.dumps(red))
        self.assertEqual(red["tunnel_endpoint"]["id"], "ipv4")


if __name__ == "__main__":
    unittest.main()
