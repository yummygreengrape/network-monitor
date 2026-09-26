"""식별자 가리기와 동의.

이 도구는 개인정보를 다룬다. 가리기가 깨지면 공유한 보고서에서 네트워크와
장소가 드러난다.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from netmon import config as configmod
from netmon import engine as enginemod
from netmon import redact as redactmod
from netmon import util
from netmon.engine import Engine
from netmon.model import ident
from netmon.store import Store
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
        """감싸지 않은 값을 문자열 추측으로 가리지 않는다 — 정해진 자유 문자열 필드 밖에서는.

        추측해서 가리면 반쯤 가려진 로그가 조용히 만들어진다. 감싸야 할 값을
        감싸지 않은 것은 스키마 버그이고, 버그로 드러나는 편이 낫다. 예외는
        공급자·데몬이 준 자유 문자열 필드뿐이다(`TestAddressesInsideFreeText`).
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
            "보낼지는 직전 주기의 상태로 정하므로 다시 연결된 직후 첫 주기에도 나갈 수 있고, "
            "공급자마다 한 끊김에 최대 12발까지만 보냅니다.")

CANON_EN = ("While a VPN is not connected (down or renegotiating) it sends ICMP "
            "to the tunnel endpoint address the provider reported — ping_count "
            "packets, 1 by default. The decision uses the previous cycle's state, "
            "so a probe may also go out on the first cycle after reconnecting, "
            "and at most 12 packets go out per provider per outage.")


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
      - 직전 주기 기준이라 다시 연결된 직후 첫 주기에도 **나갈 수 있다**
        (실제로 나가는지는 그 직전 주기의 사유에 주소가 있었는지에 달렸다 —
        "나간다" 로 단정하지 않는다)
      - 한 끊김의 상한 (12발). 세는 단위가 "구간" 이면 읽는 사람이 어느
        구간인지 알 수 없다 — 공급자 하나의 끊김 하나다 (검수 1차 지적).
    """

    def _readme(self):
        """저장소의 README. 설치본에는 없을 수 있으므로 없으면 건너뛴다.

        `netmon.__file__` 의 두 단계 위는 저장소에서만 README 가 있는
        자리다. 패키지만 설치한 환경에서는 그 파일이 없어 이 검사가
        `FileNotFoundError` 로 터진다 — 없는 파일은 실패가 아니라 검사할
        수 없는 것이다 (검수 1차 지적).
        """
        import netmon

        root = os.path.dirname(os.path.dirname(os.path.abspath(netmon.__file__)))
        path = os.path.join(root, "README.md")
        if not os.path.isfile(path):
            self.skipTest("README.md 가 없다 (저장소 밖에서 돌린 검사)")
        with open(path, encoding="utf-8") as fh:
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

    def test_the_local_record_keeps_the_provider_reason_as_it_is(self):
        """로컬 기록에는 원문을 남긴다 — 사용자 결정(2026-09-21) "기록 시점에 가리지 않는다".
        그 결정의 나머지 반쪽 "내보낼 때 가림" 은 아래 시험이 본다."""
        o = endpoint_probe(obs(vpn=vpn_state("disconnected", reason=ENDPOINT_REASON)))
        self.assertEqual(o.as_dict()["data"]["vpn"]["warp"]["reason"], ENDPOINT_REASON)

    def test_the_provider_reason_is_redacted_when_exported(self):
        """내보낼 때는 사유 속 주소가 토큰이 된다(사용자 결정 2026-09-21 "내보낼 때 가림").

        앞선 작업은 이 필드가 내보낼 때도 그대로 남는다고 시험으로 고정했는데,
        결정 기록은 기록 시점만 가리지 않기로 했다 — 내보낸 기록에 주소가 남으면
        README "개인정보" 의 약속과 어긋난다.
        """
        o = endpoint_probe(obs(vpn=vpn_state("disconnected", reason=ENDPOINT_REASON)))
        red = redactmod.redact(o.as_dict(), self.salt)
        reason = red["data"]["vpn"]["warp"]["reason"]
        self.assertNotIn(ENDPOINT, reason)
        self.assertIn(redactmod.token(self.salt, "ipv4", ENDPOINT), reason)

    def test_the_evidence_field_is_redactable(self):
        """끊김 증거에 실린 주소도 같은 방식으로 가려진다."""
        evidence = {"tunnel_endpoint": ident("ipv4", ENDPOINT),
                    "tunnel_endpoint_reachable": False}
        red = redactmod.redact(evidence, self.salt)
        self.assertNotIn(ENDPOINT, json.dumps(red))
        self.assertEqual(red["tunnel_endpoint"]["id"], "ipv4")


class TestAddressesInsideFreeText(unittest.TestCase):
    """공급자·데몬이 준 자유 문자열 속 주소도 내보낼 때 가린다 (QA-11, ADV-4).

    대상 필드는 정해져 있다: 공급자 사유(`reason`, 판정 증거의 `provider_reason`)와
    WARP 데몬 줄(`warp_daemon.lines`, 증거의 `daemon_lines`·`daemon_transitions` 의
    `text`). 주소만 토큰으로 바꾸고 포트는 남긴다. 같은 주소는 감싼 값과 같은 토큰이
    되어 "사유의 주소 = 측정한 엔드포인트" 같은 관계가 가린 뒤에도 보인다.
    """

    V6 = "2001:db8::7"

    def setUp(self):
        self.salt = b"test-salt-not-a-real-one"
        self.t4 = redactmod.token(self.salt, "ipv4", ENDPOINT)
        self.t6 = redactmod.token(self.salt, "ipv6", self.V6)

    def red(self, obj, kinds=None):
        return redactmod.redact(obj, self.salt, kinds)

    def test_ipv4_and_bracketed_ipv6_with_ports(self):
        reason = "Performing happy eyeballs to %s:2408 and [%s]:2408" % (ENDPOINT, self.V6)
        out = self.red({"vpn": {"warp": {"reason": reason}}})["vpn"]["warp"]["reason"]
        self.assertEqual(out, "Performing happy eyeballs to %s:2408 and [%s]:2408" % (self.t4, self.t6))

    def test_bare_ipv6(self):
        out = self.red({"reason": "via %s now" % self.V6})["reason"]
        self.assertEqual(out, "via %s now" % self.t6)

    def test_a_bracketed_ipv4_with_a_port(self):
        """원소 하나짜리 소켓 주소 목록 `[<IPv4>:<포트>]` — 데몬이 실제로 쓰는 모양이다.

        대괄호 갈래가 괄호 전체를 먼저 먹고 IPv6 검증에 실패하면 안쪽을 다시 훑지
        않아 주소가 그대로 나갔다(DEV-1 검수 지적 1).
        """
        for text, want in (("Unable to reach [%s:2408]" % ENDPOINT, "Unable to reach [%s:2408]" % self.t4),
                           ("addrs=[%s:53]" % ENDPOINT, "addrs=[%s:53]" % self.t4),
                           ("[%s]" % self.V6, "[%s]" % self.t6)):
            self.assertEqual(self.red({"reason": text})["reason"], want)

    def test_an_address_at_the_end_of_a_sentence_or_after_an_underscore(self):
        """문장 끝 마침표·밑줄·한글 조사에 붙은 주소도 가린다(DEV-1 검수 지적 2)."""
        for text, want in (("to %s." % ENDPOINT, "to %s." % self.t4),
                           ("via %s." % self.V6, "via %s." % self.t6),
                           ("ip_%s" % ENDPOINT, "ip_%s" % self.t4),
                           ("ip_%s" % self.V6, "ip_%s" % self.t6),
                           ("%s로 연결" % ENDPOINT, "%s로 연결" % self.t4)):
            self.assertEqual(self.red({"reason": text})["reason"], want)

    def test_an_ipv6_with_an_embedded_ipv4_is_masked_whole(self):
        """IPv4 를 품은 IPv6 표기는 IPv6 앞부분까지 한 주소로 가린다(DEV-10 — 전에는 뒤의 IPv4 만 가려 앞부분이 남았다)."""
        for v6 in ("2001:db8:1234:5678::192.0.2.1", "64:ff9b::198.51.100.7", "::ffff:192.0.2.1", "2001:db8::203.0.113.9"):
            t6 = redactmod.token(self.salt, "ipv6", v6)
            for text, want in (("to %s x" % v6, "to %s x" % t6), ("[%s]:443" % v6, "[%s]:443" % t6),
                               ("via %s." % v6, "via %s." % t6)):
                out = self.red({"reason": text})["reason"]
                self.assertEqual(out, want, text)
                self.assertNotIn(v6.split("::")[0] or "ffff", out)

    def test_an_embedded_ipv4_shape_that_is_not_an_address_stays(self):
        for text in ("at 12:34:56.789 ok", "2001:db8::192.0.2.1.5", "2001:db8:c:192.0.2.4x"):
            self.assertEqual(self.red({"reason": text})["reason"], text, text)
        # 영숫자에 붙은 IPv6 은 경계 규칙상 못 가린다(알려진 한계) — 뒤의 IPv4 는 그래도 가린다
        t4 = redactmod.token(self.salt, "ipv4", "192.0.2.1")
        self.assertEqual(self.red({"reason": "x2001:db8::192.0.2.1"})["reason"], "x2001:db8::" + t4)

    def test_an_invalid_ipv6_before_an_ipv4_still_masks_the_ipv4(self):
        """IPv6 로 유효하지 않은 앞부분에 붙은 IPv4 는 옛 경로처럼 IPv4 만 가린다(DEV-10 2회차 — 새 가지가 통째로 원문을 남기던 후퇴)."""
        t4 = redactmod.token(self.salt, "ipv4", "192.0.2.1")
        t4b = redactmod.token(self.salt, "ipv4", "198.51.100.7")
        for text, want in (("to :::192.0.2.1 x", "to :::%s x" % t4), ("to ::::::192.0.2.1 x", "to ::::::%s x" % t4),
                           ("to 2001:db8:192.0.2.1 x", "to 2001:db8:%s x" % t4),
                           ("to :2408::198.51.100.7 x", "to :2408::%s x" % t4b),
                           ("to 2001::db8::192.0.2.1 x", "to 2001::db8::%s x" % t4),
                           ("[2001:db8:192.0.2.1]:443", "[2001:db8:%s]:443" % t4)):
            self.assertEqual(self.red({"reason": text})["reason"], want, text)

    def test_more_shapes_of_an_embedded_ipv4(self):
        """`::` 뒤 바로 IPv4, 여섯 그룹 + IPv4, 영역 표시, `::` 뒤 다섯 그룹 + IPv4, 대괄호 없는 포트."""
        for v6, rest in (("::192.0.2.1", " x"), ("2001:db8:1:2:3:4:192.0.2.1", " x"), ("2001:db8::192.0.2.1%en0", " x"),
                         ("::2001:db8:1:2:3:192.0.2.1", " x"), ("2001:db8::192.0.2.1", ":2408 x")):
            t6 = redactmod.token(self.salt, "ipv6", v6)
            self.assertEqual(self.red({"reason": "to " + v6 + rest})["reason"], "to " + t6 + rest, v6)

    def test_an_embedded_ipv4_is_masked_when_only_ipv4_is_asked(self):
        t4 = redactmod.token(self.salt, "ipv4", "192.0.2.1")
        out = self.red({"reason": "to 2001:db8::192.0.2.1 x"}, kinds={"ipv4"})["reason"]
        self.assertEqual(out, "to 2001:db8::%s x" % t4)

    def test_a_non_ascii_digit_next_to_an_address_does_not_unmask_it(self):
        """DEV-10 3회차: 주소 옆의 비ASCII 숫자(전각·아랍-인도)가 가림을 무너뜨리지 않는다 — 주소 정규식은 ASCII 숫자만 숫자로 본다."""
        for text, gone in (("to 2001:db8::\uff1192.0.2.1 x", ("2001:db8",)),
                           ("to ::ffff:192.0.2.1\uff11.\uff11 x", ("192.0.2.1",)),
                           ("to :::203.0.113.9\u0663.\u0663 x", ("203.0.113.9",)),
                           ("to 192.0.2.1\uff11 x", ("192.0.2.1",)),
                           ("to 192.0.2.1.\uff11 x", ("192.0.2.1",))):     # IPv4 뒤 점 + 비ASCII 숫자(끝 둘러보기 `\.[0-9]`)
            out = self.red({"reason": text})["reason"]
            for g in gone:
                self.assertNotIn(g, out, text)

    def test_an_address_right_after_a_zone_is_still_masked(self):
        """DEV-10 3회차 검수 [중간]: 영역 표시(`%…`)를 단 IPv4 품은 IPv6 바로 뒤에 콜론으로 이어진 주소가 오면, 영역 표시가 그 주소의 첫
        그룹을 삼켜 뒤 IPv6 이 남던 후퇴 — 내보내기(`redact_text`)와 저장(`scrub_daemon_text`) 둘 다. 영역 표시는 뒤에 콜론이 오면 영역 표시로
        보지 않는다(맨 IPv6 갈래와 같은 끝 조건)."""
        from netmon.vpn import scrub_daemon_text
        for text, gone in (("to ::192.0.2.1%2001:db8::1 x", "db8::1"),
                           ("to 2001:db8:192.0.2.1%2001:db8::7 x", "db8::7"),     # 앞 후보가 IPv6 로 무효 — 되돌림 경로
                           ("to ::192.0.2.1%_2001:db8::1 x", "db8::1"),
                           ("to ::192.0.2.1%\uff112001:db8::1 x", "db8::1"),
                           ("to ::192.0.2.1%1:2::3 x", "2::3")):
            self.assertNotIn(gone, self.red({"reason": text})["reason"], text)
            self.assertNotIn(gone, scrub_daemon_text(text), text)

    def test_the_edges_of_the_embedded_ipv4_branch(self):
        """DEV-10 3회차: 뒤 콜론은 막지 않음, 앞 점 뒤에서 시작하지 않음, 뒤 IPv4 가 주소가 아니면 되돌림도 가리지 않음, 되돌림은 뒤 글(영역 표시)을
        지킴."""
        t4 = redactmod.token(self.salt, "ipv4", "192.0.2.1")
        t6 = redactmod.token(self.salt, "ipv6", "2001:db8::192.0.2.1")
        for text, want in (("to 2001:db8::192.0.2.1: refused", "to %s: refused" % t6),
                           ("a.b::192.0.2.1 x", "a.b::%s x" % t4),
                           ("to 2001:db8::999.0.2.1 x", "to 2001:db8::999.0.2.1 x"),
                           ("to 2001:db8:192.0.2.1%en0 x", "to 2001:db8:%s%%en0 x" % t4)):
            self.assertEqual(self.red({"reason": text})["reason"], want, text)

    def test_same_address_same_token_as_the_wrapped_value(self):
        d = {"reason": ENDPOINT_REASON, "tunnel_endpoint": ident("ipv4", ENDPOINT)}
        out = self.red(d)
        self.assertIn(out["tunnel_endpoint"]["v"], out["reason"])

    def test_evidence_provider_reason(self):
        out = self.red({"evidence": {"provider_reason": ENDPOINT_REASON}})
        self.assertNotIn(ENDPOINT, json.dumps(out))

    def test_daemon_lines_everywhere_they_are_kept(self):
        line = {"ts": "2026-01-01T00:00:00.000Z", "kind": "error",
                "text": "SocketRecv to %s:443 failed" % ENDPOINT}
        d = {"data": {"warp_daemon": {"lines": [dict(line)]}},
             "evidence": {"daemon_lines": [dict(line)], "daemon_transitions": [dict(line)]}}
        out = json.dumps(self.red(d))
        self.assertNotIn(ENDPOINT, out)
        self.assertEqual(out.count(self.t4), 3)

    def test_things_that_are_not_addresses_stay(self):
        """모듈 경로의 `::`, 시각, MAC 모양, 판 번호는 주소가 아니다 (ADV-4)."""
        text = ("2026-09-23T04:15:27.493Z WARN main_loop: warp::warp_service: at 12:34:56 "
                "mac 00:00:5e:00:53:01 v1.2.3 ratio 3:1 :: handler::cafe build 192.0.2.1.5 "
                "ver 2026.7.1376.0")
        self.assertEqual(self.red({"reason": text})["reason"], text)

    def test_the_kinds_filter_is_respected(self):
        out = self.red({"reason": ENDPOINT_REASON}, kinds={"mac"})
        self.assertEqual(out["reason"], ENDPOINT_REASON)

    def test_other_untagged_fields_are_still_left_alone(self):
        out = self.red({"note": ENDPOINT_REASON, "text": ENDPOINT_REASON})
        self.assertEqual(out["note"], ENDPOINT_REASON)
        self.assertEqual(out["text"], ENDPOINT_REASON)

    def test_adversarial_strings_finish_quickly(self):
        """콜론·점·16진이 끝없이 이어진 문자열에서도 멈추지 않는다 (ADV-4)."""
        import time
        for text in ("1:" * 40000, "a:" * 40000, "1." * 40000, "f" * 80000 + ":", "[" * 40000,
                     "_1:" * 30000, "[1:" * 30000 + "]", "1:1." * 30000, "::1.1.1." * 20000):
            start = time.time()
            self.assertEqual(self.red({"reason": text})["reason"], text)
            self.assertLess(time.time() - start, 2.0, text[:8])
        start = time.time()                         # 콜론이 끝없이 이어진 뒤의 IPv4 — 가리되 멈추지 않는다
        out = self.red({"reason": ":" * 80000 + ENDPOINT})["reason"]
        self.assertLess(time.time() - start, 2.0)
        self.assertNotIn(ENDPOINT, out)
        start = time.time()                         # 긴 영역 표시 뒤 콜론 — 영역 표시 끝 조건이 되돌아가며 다시 봐도 멈추지 않는다(DEV-10 4회차)
        self.red({"reason": ("::192.0.2.1%" + "a" * 50 + ":") * 4000 + "::192.0.2.1%" + "a" * 100000 + ":"})
        self.assertLess(time.time() - start, 2.0)


class TestACollectorFailureCarriesNoPath(unittest.TestCase):
    """수집기가 던진 예외의 **메시지**는 관측에 실리지 않는다 (DEV-15, AC-5).

    `Observation.errors` 는 `as_dict` 에 그대로 실리고(netmon/model.py),
    `capture` 는 그 결과를 파일로 내보낸다. `--redact` 는 `ident()` 로 감싼
    값과 공급자·데몬 자유 문자열 필드만 바꾸므로(netmon/redact.py) 이 필드의
    감싸지 않은 문장은 가려지지 않는다.
    그런데 subprocess 는 실행 실패 예외에 **실행 파일 경로**를 담는다.

    **문자열을 손으로 만들어 넣지 않는다** — 실제로 실행 실패를 일으켜
    파이썬이 만든 예외를 쓴다. 손으로 만든 문자열은 실제 경로를 덮지 못한다.
    """

    #: 엔진이 한 주기에 부르는 수집기들. 하나만 터뜨리고 나머지는 비운다.
    COLLECTORS = ("iface", "arp", "dhcp", "dns", "route", "wifi", "link")

    def setUp(self):
        self.salt = b"test-salt-not-a-real-one"
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.bad = os.path.join(self.dir, "netmon-not-a-binary")
        with open(self.bad, "w", encoding="utf-8") as fh:
            fh.write("실행 형식이 아니다\n")
        os.chmod(self.bad, 0o755)

    def _explode(self, *_args, **_kwargs):
        """실행 실패를 실제로 일으킨다. `util.run` 이 잡지 않는 갈래다."""
        util.run([self.bad])
        raise AssertionError("실행이 실패해야 한다")

    def _engine(self):
        cfg = configmod.load(os.path.join(self.dir, "no-config.json"))
        return Engine(cfg, Store(self.dir))

    def _observe(self, victim):
        eng = self._engine()
        with mock.patch.multiple(
                enginemod,
                **{name: mock.Mock(collect=(self._explode if name == victim
                                            else (lambda ctx: {})))
                   for name in self.COLLECTORS}):
            return eng.observe()

    def test_the_exception_really_carries_the_path(self):
        """이 시험의 재료가 실재함을 먼저 못 박는다.

        여기가 깨지면 아래 시험은 아무것도 가리지 않는 빈 시험이 된다.
        """
        with self.assertRaises(OSError) as caught:
            util.run([self.bad])
        self.assertIn(self.bad, str(caught.exception))

    def test_the_message_never_reaches_the_observation(self):
        o = self._observe("iface")
        self.assertEqual(o.errors, {"iface": "OSError"})
        for text in (json.dumps(o.as_dict(), ensure_ascii=False),
                     json.dumps(redactmod.redact(o.as_dict(), self.salt),
                                ensure_ascii=False)):
            self.assertNotIn(self.bad, text)
            self.assertNotIn(self.dir, text)
            self.assertNotIn("Exec format error", text)

    def test_the_vpn_query_is_the_same(self):
        """공급자 조회 갈래도 같다 — 그쪽도 외부 명령을 쓴다."""
        eng = self._engine()
        eng.cfg.set_feature("vpn.enabled", True)
        with mock.patch.multiple(
                enginemod,
                **{name: mock.Mock(collect=(lambda ctx: {}))
                   for name in self.COLLECTORS}), \
             mock.patch.object(enginemod.vpn, "resolve",
                               return_value=["warp"]), \
             mock.patch.object(enginemod.vpn, "collect", self._explode), \
             mock.patch.object(enginemod.vpn, "read_warp_daemon",
                               return_value=([], None, {"read": "missing",
                                                        "skipped_bytes": 0,
                                                        "reset": True})):
            # warp 가 공급자면 데몬 로그도 읽는다 — 이 기계의 실제 파일에 닿지 않게 막는다.
            o = eng.observe()
        self.assertEqual(o.errors, {"vpn": "OSError"})
        text = json.dumps(redactmod.redact(o.as_dict(), self.salt),
                          ensure_ascii=False)
        self.assertNotIn(self.bad, text)
        self.assertNotIn(self.dir, text)


if __name__ == "__main__":
    unittest.main()
