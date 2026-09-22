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

        **문구가 무엇을 말해야 하는지는 아래
        `TestTheFourTextsSayTheSameThing` 가 본다.** 여기서 보던
        "끊긴" 단언은 지웠다 — `connecting` 을 "끊김" 이라 부르지 않기로 한
        결정(AC-9)과 어긋나고, 실제 동작(`disconnected`·`connecting` 둘 다)
        보다 좁게 적는 문구를 고정하고 있었다 (AC-4 수정분).
        """
        from netmon import messages

        self.assertIn(self.FEATURE, configmod.CONSENTS["external_probes"]["enables"])
        self.assertIn("터널", messages.get("WZ_EXTERNAL_BODY", "ko"))
        self.assertIn("tunnel endpoint", messages.get("WZ_EXTERNAL_BODY", "en"))


# 네 곳이 같은 문장으로 적어야 하는 것 (AC-4 수정분, 사용자 결정 2026-09-22).
# 여기 있는 글자가 정본이다.
CANON_KO = ("VPN 이 연결돼 있지 않은 동안(끊김·재협상) 공급자가 사유에 적어 준 "
            "터널 상대편(엔드포인트) 주소로 ICMP 를 보냅니다(ping_count 만큼, 기본 1발). "
            "보낼지는 직전 주기의 상태로 정하므로 다시 연결된 직후 첫 주기에도 한 번 나가고, "
            "한 구간에 최대 12번까지만 보냅니다.")

CANON_EN = ("While a VPN is not connected (down or renegotiating) it sends ICMP "
            "to the tunnel endpoint address the provider reported — ping_count "
            "packets, 1 by default. The decision uses the previous cycle's state, "
            "so one probe also goes out on the first cycle after reconnecting, "
            "and at most 12 go out per stretch.")


def _flat(text):
    """줄바꿈·들여쓰기만 다른 같은 문장을 비교할 수 있게 편다."""
    return " ".join(text.split())


class TestTheFourTextsSayTheSameThing(unittest.TestCase):
    """README·동의 설명·마법사 문구가 한 문장으로 통일돼 있는가 (AC-4 수정분).

    네 곳이 갈려 있었다 — README 만 코드와 맞고 나머지 셋은 "VPN 이 끊긴
    동안" 이라 `connecting` 주기를 빠뜨렸다. 읽는 사람이 어느 것이 실제
    동작인지 알 수 없는 상태였고, 고칠 때 한 곳만 고치면 다시 갈린다.

    문장에는 네 가지가 들어 있어야 한다.
      - 어떤 상태에 보내는가 (연결돼 있지 않은 동안 — 끊김·재협상 둘 다)
      - 몇 발인가 (`ping_count` 만큼. "한 발" 로 단정하지 않는다)
      - 직전 주기 기준이라 다시 연결된 직후 첫 주기에도 나간다
      - 한 구간의 상한 (12번)
    """

    def _readme(self):
        import netmon

        root = os.path.dirname(os.path.dirname(os.path.abspath(netmon.__file__)))
        with open(os.path.join(root, "README.md"), encoding="utf-8") as fh:
            return fh.read()

    def test_the_readme_carries_the_sentence(self):
        self.assertIn(CANON_KO, _flat(self._readme()))

    def test_the_consent_text_carries_the_sentence(self):
        self.assertIn(CANON_KO,
                      _flat(configmod.CONSENTS["external_probes"]["sends_out"]))

    def test_the_wizard_carries_the_sentence(self):
        from netmon import messages

        self.assertIn(CANON_KO, _flat(messages.get("WZ_EXTERNAL_BODY", "ko")))
        self.assertIn(CANON_EN, _flat(messages.get("WZ_EXTERNAL_BODY", "en")))

    def test_the_purpose_text_uses_the_same_condition(self):
        """`why` 는 목적을 적는 자리라 문장이 다르지만 조건은 같아야 한다."""
        self.assertIn("연결돼 있지 않은 동안(끊김·재협상)",
                      _flat(configmod.CONSENTS["external_probes"]["why"]))

    def test_no_text_calls_renegotiation_a_disconnection(self):
        """`connecting` 을 "끊김" 이라고 적지 않는다 (AC-9).

        그렇게 적으면 실제로 보내는 두 상태 중 하나가 문구에서 사라진다.
        """
        from netmon import messages

        texts = [_flat(self._readme()),
                 _flat(configmod.CONSENTS["external_probes"]["why"]),
                 _flat(configmod.CONSENTS["external_probes"]["sends_out"]),
                 _flat(messages.get("WZ_EXTERNAL_BODY", "ko")),
                 _flat(messages.get("WZ_ROW_EXTERNAL", "ko"))]
        for text in texts:
            for wrong in ("VPN 이 끊긴 동안", "VPN 이 끊긴 주기", "끊겨 있는 주기에만"):
                self.assertNotIn(wrong, text)

    def test_the_summary_row_names_the_condition(self):
        """한 줄 요약도 언제 나가는지는 밝힌다."""
        from netmon import messages

        self.assertIn("비연결 주기", messages.get("WZ_ROW_EXTERNAL", "ko"))
        self.assertIn("not connected", messages.get("WZ_ROW_EXTERNAL", "en"))

    def test_the_readme_does_not_promise_a_single_packet(self):
        """발 수는 `ping_count` 가 정한다. 설정과 무관하게 단정하지 않는다."""
        readme = _flat(self._readme())
        self.assertNotIn("ICMP 한 발", readme)
        self.assertIn("ping_count 만큼", readme)


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
