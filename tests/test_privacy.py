"""식별자 가리기와 동의.

이 도구는 개인정보를 다룬다. 가리기가 깨지면 공유한 보고서에서 네트워크와
장소가 드러난다.
"""
from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import random
import shutil
import tempfile
import unittest
from unittest import mock

from netmon import __main__ as climod
from netmon import config as configmod
from netmon import engine as enginemod
from netmon import redact as redactmod
from netmon import util
from netmon.collect import wifi as wificol
from netmon.engine import Engine
from netmon.model import ident, unwrap
from netmon.store import Store
from tests.helpers import (BSSID, ENDPOINT, ENDPOINT_REASON, GW, GW_MAC, GW_MAC_ALT, SSID,
                           endpoint_probe, obs, vpn_state)

# 진짜 Wi-Fi 수집기. 시험이 엔진 쪽 `collect` 를 바꿔 끼운 뒤에도 이것을 부른다.
_REAL_WIFI_COLLECT = wificol.collect


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
        """README 는 영어 본문과 한국어 요약으로 되어 있다 — 두 언어 모두 같은 문장을 싣는다."""
        self.assertIn(CANON_EN, _flat(self._readme()))
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
        # README 영어 본문도 같다 — 재협상 주기를 빠뜨린 영어 표현을 막는다.
        for wrong in ("while the vpn is down", "while a vpn is down", "only while disconnected"):
            self.assertNotIn(wrong, _flat(self._readme()).lower())

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
        self.assertNotIn("a single icmp", readme.lower())
        self.assertIn("ping_count packets", readme)


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
        README "Privacy" 의 약속과 어긋난다.
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

    def test_an_upper_case_prefix_with_an_ipv4_tail_is_masked_whole(self):
        """대문자 16진 접두도 IPv4 를 품은 IPv6 으로 통째로 가린다(FINAL 1회차 [낮음] R1: 접두를 소문자로 좁힌 변이가 전체 시험을
        통과했다 — 좁히면 뒤의 IPv4 만 가려 IPv6 앞부분이 남는다)."""
        for v6 in ("2001:DB8::192.0.2.1", "::FFFF:192.0.2.1", "64:FF9B::192.0.2.1"):
            t6 = redactmod.token(self.salt, "ipv6", v6)
            self.assertEqual(self.red({"reason": "to " + v6 + " x"})["reason"], "to " + t6 + " x", v6)

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


# ───────────────────────── 실행 중인 netmon 의 동의 철회 (작업 2026-09-28-consent-revoke-running-agent)
#
# 설정은 시작할 때 한 번 읽혔고 철회는 파일만 고쳤다 — 위치 동의를 물려도 재시작 전까지 SSID·BSSID 를 계속 기록하고, 외부 점검 동의를
# 물려도 터널 엔드포인트 ICMP 를 계속 보냈다. 아래 시험은 실제 `Engine.cycle` 을 돌리고(수집기의 `collect` 만 바꿔 끼움), Wi-Fi 수집기는
# 진짜 것을 쓴다 — 동의 게이트가 수집기 안(netmon/collect/wifi.py)에 있기 때문이다. 철회는 실제 CLI(`netmon consent revoke`)로 한다.

# 동의가 걸린 기능 다섯 개(netmon/config.py FEATURE_CONSENT).
FIVE = ("detect.evil_twin", "detect.public_ip", "detect.dns_intercept", "detect.tls_intercept", "vpn.tunnel_probe")
# Wi-Fi 를 뺀 수집기. 이것들은 준비한 관측 블록을 그대로 돌려준다.
FAKED = ("iface", "arp", "dhcp", "route", "dns", "link")

# SPEC AC-2 의 "못 읽음" 모양. (이름, 파일 내용 바이트 또는 None = 파일 없음)
UNREADABLE = [
    ("파일 없음", None),
    ("빈 파일", b""),
    ("잘린 JSON", b'{"consents": {"location": {"granted": fal'),
    ("최상위 목록", b"[]"),
    ("최상위 null", b"null"),
    ("최상위 숫자", b"5"),
    ("최상위 문자열", b'"x"'),
    ("consents null", b'{"consents": null}'),
    ("consents 목록", b'{"consents": []}'),
    ("동의 값 true", b'{"consents": {"location": true, "external_probes": true}}'),
    ("동의 값 문자열", b'{"consents": {"location": "yes", "external_probes": "yes"}}'),
    ("granted 문자열 false", b'{"consents": {"location": {"granted": "false"}, "external_probes": {"granted": "false"}}}'),
    ("granted 문자열 true", b'{"consents": {"location": {"granted": "true"}, "external_probes": {"granted": "true"}}}'),
    ("granted 0", b'{"consents": {"location": {"granted": 0}, "external_probes": {"granted": 0}}}'),
    ("granted 1", b'{"consents": {"location": {"granted": 1}, "external_probes": {"granted": 1}}}'),
    ("granted null", b'{"consents": {"location": {"granted": null}, "external_probes": {"granted": null}}}'),
    ("features null", b'{"consents": {"location": {"granted": true}, "external_probes": {"granted": true}}, "features": null}'),
    ("features 목록", b'{"consents": {"location": {"granted": true}, "external_probes": {"granted": true}}, "features": []}'),
    # json 이 ValueError 가 아닌 RecursionError 를 낸다(PLAN 검수 1회차).
    ("깊은 중첩", b"[" * 100000),
    ("읽기 권한 없음", "NOPERM"),
    ("경로가 디렉터리", "DIR"),
]

# 동의 게이트 기능이 켜진 파일에서만 드러나는 모양 — 기능이 꺼져 있으면 `effective` 가 동의를 읽기 전에 거짓을 돌려줘 예외도 동의도 가려진다.
_ON = b'"features": {"detect.evil_twin": true, "detect.public_ip": true, "detect.dns_intercept": true, "detect.tls_intercept": true, "vpn.tunnel_probe": true, "vpn.enabled": true}'
UNREADABLE += [
    ("consents null·기능 켬", b'{"consents": null, ' + _ON + b"}"),
    ("consents 목록·기능 켬", b'{"consents": [], ' + _ON + b"}"),
    ("동의 값 true·기능 켬", b'{"consents": {"location": true, "external_probes": true}, ' + _ON + b"}"),
    ("granted 문자열 false·기능 켬", b'{"consents": {"location": {"granted": "false"}, "external_probes": {"granted": "false"}}, ' + _ON + b"}"),
    ("한 동의만 granted 문자열·기능 켬", b'{"consents": {"location": {"granted": true}, "external_probes": {"granted": "yes"}}, ' + _ON + b"}"),
]


def _ssid_part(key):
    """판정·상태의 `network` 키에서 SSID 자리(첫 `|` 와 마지막 `|` 사이). 시험 쪽 독립 구현이다."""
    if not isinstance(key, str) or key.count("|") < 2:
        return None
    return key[key.index("|") + 1:key.rindex("|")]


def _cli(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = climod.main(list(argv))
    return rc, out.getvalue()


class Live:
    """실행 중인 netmon 하나. 설정 파일·기록 폴더는 임시 폴더에 있다."""

    def __init__(self, tc, grant=True):
        self.tc = tc
        self.dir = tempfile.mkdtemp()
        tc.addCleanup(shutil.rmtree, self.dir, True)
        self.path = os.path.join(self.dir, "config.json")
        cfg = configmod.load(self.path)
        cfg.set_feature("vpn.enabled", True)
        cfg.set_feature("vpn.providers", ["macos"])
        if grant:
            for c in ("location", "external_probes"):
                cfg.grant(c)
            for f in FIVE:
                cfg.set_feature(f, True)
        cfg.save()
        self.data = os.path.join(self.dir, "data")
        self.world = obs(ssid=SSID, bssid=BSSID)
        # 끊긴 VPN — 사유에 공인 엔드포인트가 있다. 동의·기능이 켜져 있으면 다음 주기에 그 주소가 수집기로 넘어간다.
        self.vpn = vpn_state("disconnected", reason=ENDPOINT_REASON, provider="macos")
        self.link_up = True
        self.wall = 1000.0
        self.ctxs = {}
        self.during_observe = None
        self.engine = self.start()

    # --- 프로세스 ---
    def start(self):
        """`cmd_run` 과 같은 순서 — 시작 때 설정을 읽어 엔진을 만든다."""
        return Engine(configmod.load(self.path), Store(self.data))

    def restart(self):
        self.engine = self.start()
        return self.engine

    # --- 수집기 ---
    def _fake(self, name):
        def collect(ctx=None):
            self.ctxs[name] = dict(ctx or {})
            block = copy.deepcopy(self.world.data.get(name, {}))
            if name == "iface" and not self.link_up:
                block.update(primary=None, primary_kind="unknown", default4_iface=None,
                             default4_gateway=None, scoped_gateway=None)
            return block
        return collect

    def _wifi(self, ctx):
        """진짜 Wi-Fi 수집기. 명령 실행과 파싱만 바꿔 끼운다 — 이 프로세스에 위치 권한이 있는 경우(가장 단순한 갈래)."""
        self.ctxs["wifi"] = dict(ctx)
        if self.during_observe:
            hook, self.during_observe = self.during_observe, None
            hook()
        parsed = {"ssid": SSID, "bssid": BSSID, "security": "WPA2", "link_active": "TRUE"}
        with mock.patch.object(wificol, "run", return_value=mock.Mock(out="")), \
                mock.patch.object(wificol, "parse_wifi_summary", return_value=parsed), \
                mock.patch.object(wificol, "location_state", return_value="granted"):
            return _REAL_WIFI_COLLECT(ctx)

    @contextlib.contextmanager
    def collectors(self):
        """수집기의 `collect` 만 바꿔 끼운다 — 모듈의 다른 함수(엔진이 쓰는 `link.packets_per_command` 등)는 진짜다."""
        with contextlib.ExitStack() as stack:
            for n in FAKED:
                stack.enter_context(mock.patch.object(getattr(enginemod, n), "collect", side_effect=self._fake(n)))
            stack.enter_context(mock.patch.object(enginemod.wifi, "collect", side_effect=self._wifi))
            stack.enter_context(mock.patch.object(enginemod.vpn, "resolve", return_value=["macos"]))
            stack.enter_context(mock.patch.object(enginemod.vpn, "collect",
                                                  side_effect=lambda _p: copy.deepcopy(self.vpn)))
            yield

    def cycle(self, step=5.0):
        self.wall += step
        self.ctxs = {}
        with self.collectors():
            o, f = self.engine.cycle(now=self.wall)
        self.engine.persist(o, f)
        return o, f

    # --- 설정 파일 ---
    def revoke(self, item):
        rc, out = _cli("--config", self.path, "consent", "revoke", item)
        self.tc.assertEqual(rc, 0, out)
        return out

    def grant_on_disk(self):
        cfg = configmod.load(self.path)
        for c in ("location", "external_probes"):
            cfg.grant(c)
        for f in FIVE:
            cfg.set_feature(f, True)
        cfg.save()

    def write_raw(self, content):
        if os.path.isdir(self.path):
            os.rmdir(self.path)
        elif os.path.exists(self.path):
            os.chmod(self.path, 0o600)
            os.remove(self.path)
        if content is None:
            return
        if content == "DIR":
            os.mkdir(self.path)
            return
        if content == "NOPERM":
            with open(self.path, "w", encoding="utf-8") as fh:
                fh.write('{"consents": {}}')
            os.chmod(self.path, 0)
            self.tc.addCleanup(lambda: os.path.exists(self.path) and os.chmod(self.path, 0o600))
            return
        with open(self.path, "wb") as fh:
            fh.write(content)

    # --- 기록 ---
    def lines(self):
        """기록 폴더의 표본·이벤트 줄. {파일 이름: [줄]}"""
        out = {}
        if os.path.isdir(self.data):
            for name in sorted(os.listdir(self.data)):
                if name.endswith(".jsonl"):
                    with open(os.path.join(self.data, name), encoding="utf-8") as fh:
                        out[name] = fh.read().splitlines()
        return out

    def new_lines(self, before):
        now = self.lines()
        return [line for name, ls in now.items() for line in ls[len(before.get(name, [])):]]

    def state_on_disk(self):
        return Store(self.data).load_state()

    def baseline_on_disk(self):
        return Store(self.data).load_baseline()


def _wifi_ident(sample_wifi):
    """(SSID, BSSID) — 감싼 값(`ident`)이면 벗긴다. 표본에서 읽은 dict 도 같은 모양이다."""
    w = sample_wifi or {}
    return unwrap(w.get("ssid")), unwrap(w.get("bssid"))


class TestUnreadableConfigFiles(unittest.TestCase):
    """ADV-1: 설정 파일 경계 모양."""

    def test_starting_on_a_bad_file_does_not_crash_and_means_no_consent(self):
        for name, content in UNREADABLE:
            with self.subTest(name):
                L = Live(self, grant=False)
                L.write_raw(content)
                L.restart()
                o, _ = L.cycle()
                self.assertFalse(L.ctxs["wifi"]["allow_location"])
                self.assertFalse(L.ctxs["link"]["allow_tunnel_probe"])
                self.assertEqual(_wifi_ident(o.data["wifi"]), (None, None))
                for f in FIVE:
                    self.assertFalse(L.engine.cfg.effective(f), f)

    def test_the_cycle_view_reads_nothing_from_a_bad_file(self):
        for name, content in UNREADABLE:
            with self.subTest(name):
                L = Live(self, grant=False)
                L.write_raw(content)
                self.assertIsNone(configmod.read_consent_view(L.path))

    def test_the_cycle_view_reads_a_good_file(self):
        L = Live(self)
        view = configmod.read_consent_view(L.path)
        self.assertIsNotNone(view)
        L.revoke("location")
        view = configmod.read_consent_view(L.path)
        self.assertFalse(view.consented("location"))
        self.assertTrue(view.consented("external_probes"))
        for good in (b"{}", b'{"consents": {}}', b'{"consents": {"location": {"granted": false}}}'):
            L.write_raw(good)
            self.assertIsNotNone(configmod.read_consent_view(L.path), good)


class TestRevokingLocationWhileRunning(unittest.TestCase):
    """QA-1: 위치 동의를 물리면 다음 주기부터 SSID·BSSID 가 새로 기록되지 않는다."""

    def test_the_precondition_the_ssid_is_recorded_while_consented(self):
        """재료 확인 — 이 갈래에서 동의가 있으면 정말 SSID 가 기록된다. 여기가 깨지면 아래 "없음" 단언은 헛통과다."""
        L = Live(self)
        o, _ = L.cycle()
        self.assertIsNotNone(_wifi_ident(o.data["wifi"])[0])
        self.assertTrue(L.ctxs["wifi"]["allow_location"])
        self.assertEqual(L.engine.identity_ssid, SSID)
        self.assertEqual(_ssid_part(L.state_on_disk().get("network")), SSID)

    def test_the_next_cycle_after_revoking_records_no_ssid_or_bssid(self):
        L = Live(self)
        L.cycle()
        L.cycle()
        out = L.revoke("location")
        before = L.lines()
        o, findings = L.cycle()
        self.assertFalse(L.ctxs["wifi"]["allow_location"])
        self.assertEqual(_wifi_ident(o.data["wifi"]), (None, None))
        self.assertTrue(o.data["wifi"].get("identity_withheld"))
        self.assertIsNone(L.engine.identity_ssid)
        for f in findings:
            self.assertIn(_ssid_part(f.network), ("-", None), f.kind)
        self.assertEqual(_ssid_part(L.state_on_disk().get("network")), "-")
        added = L.new_lines(before)
        self.assertTrue(added, "표본이 기록돼야 한다")
        for line in added:
            self.assertNotIn(SSID, line)
            self.assertNotIn(BSSID, line)
        self.assertIn(L.path, out)

    def test_the_snapshot_drops_the_ssid_at_its_next_save(self):
        """스냅샷(baseline.json)은 60초마다 저장된다 — 철회 뒤 저장이 돌아온 완전한 주기에 SSID 가 빠진다."""
        L = Live(self)
        L.cycle()
        self.assertEqual(L.baseline_on_disk().get("identity_ssid"), SSID)
        L.revoke("location")
        L.cycle(step=61.0)
        saved = L.baseline_on_disk()
        self.assertIsNone(saved.get("identity_ssid"))
        self.assertEqual(_wifi_ident(saved["data"]["wifi"]), (None, None))
        self.assertNotIn(SSID, json.dumps(saved, ensure_ascii=False))

    def test_turning_off_only_the_feature_also_applies_next_cycle(self):
        """동의는 두고 위치가 필요한 기능(`detect.evil_twin`)만 꺼도 다음 주기부터 — 좁히는 방향이다(SPEC ASSUMED 5)."""
        L = Live(self)
        L.cycle()
        cfg = configmod.load(L.path)
        cfg.set_feature("detect.evil_twin", False)
        cfg.save()
        o, _ = L.cycle()
        self.assertFalse(L.ctxs["wifi"]["allow_location"])
        self.assertEqual(_wifi_ident(o.data["wifi"]), (None, None))


class TestRevokingExternalProbesWhileRunning(unittest.TestCase):
    """QA-2: 외부 점검 동의를 물리면 다음 주기부터 터널 엔드포인트로 보내지 않는다."""

    def _armed(self):
        L = Live(self)
        L.cycle()          # 첫 주기 — 직전 VPN 관측이 없어 주소가 없다
        L.cycle()          # 직전 주기의 사유에서 주소를 고른다
        self.assertTrue(L.ctxs["link"]["allow_tunnel_probe"])
        self.assertEqual(L.ctxs["link"]["tunnel_endpoint"], ENDPOINT)
        return L

    def test_the_next_cycle_after_revoking_sends_nothing_to_the_endpoint(self):
        L = self._armed()
        L.revoke("external_probes")
        L.cycle()
        ctx = L.ctxs["link"]
        self.assertFalse(ctx["allow_tunnel_probe"])
        self.assertFalse(ctx["allow_external"])
        self.assertIsNone(ctx["tunnel_endpoint"])

    def test_turning_off_only_the_feature_also_applies_next_cycle(self):
        L = self._armed()
        cfg = configmod.load(L.path)
        cfg.set_feature("vpn.tunnel_probe", False)
        cfg.save()
        L.cycle()
        self.assertFalse(L.ctxs["link"]["allow_tunnel_probe"])
        self.assertIsNone(L.ctxs["link"]["tunnel_endpoint"])


class TestTheCliLoopsPickItUp(unittest.TestCase):
    """QA-3: 실제 `run`·`capture` 루프 — 두 주기 사이(잠드는 자리)에 실제 CLI 로 철회한다."""

    def _loop(self, L, argv_tail):
        revoked = []

        def sleep(_s):
            if not revoked:
                L.revoke("location")
                revoked.append(True)

        with L.collectors(), mock.patch.object(climod.time, "sleep", side_effect=sleep), \
                contextlib.redirect_stdout(io.StringIO()):
            rc = climod.main(["--config", L.path, "--log-dir", L.data] + argv_tail)
        self.assertEqual(rc, 0)
        self.assertTrue(revoked)

    def test_capture(self):
        L = Live(self)
        out_path = os.path.join(L.dir, "cap.jsonl")
        self._loop(L, ["capture", "3", "-o", out_path])
        with open(out_path, encoding="utf-8") as fh:
            rows = [json.loads(x) for x in fh.read().splitlines()]
        self.assertEqual(len(rows), 3)
        self.assertEqual(_wifi_ident(rows[0]["data"]["wifi"])[0], SSID, "재료 확인 — 철회 전 주기는 SSID 가 있다")
        for r in rows[1:]:
            self.assertEqual(_wifi_ident(r["data"]["wifi"]), (None, None))
            self.assertNotIn(SSID, json.dumps(r, ensure_ascii=False))

    def test_run(self):
        L = Live(self)
        self._loop(L, ["run", "--count", "3"])
        samples = [json.loads(x) for name, ls in L.lines().items() if name.startswith("samples-") for x in ls]
        self.assertEqual(len(samples), 3)
        self.assertEqual(_wifi_ident(samples[0]["data"]["wifi"])[0], SSID, "재료 확인")
        for s in samples[1:]:
            self.assertEqual(_wifi_ident(s["data"]["wifi"]), (None, None))
            self.assertNotIn(SSID, json.dumps(s, ensure_ascii=False))


class TestGrantingWhileRunningWaitsForARestart(unittest.TestCase):
    """QA-4: 동의를 **주는** 것은 실행 중인 엔진에 반영되지 않는다(Q1)."""

    def test_a_grant_on_disk_is_not_picked_up(self):
        L = Live(self, grant=False)
        L.cycle()
        L.grant_on_disk()
        L.cycle()
        L.cycle()
        self.assertFalse(L.ctxs["wifi"]["allow_location"])
        self.assertFalse(L.ctxs["link"]["allow_tunnel_probe"])
        self.assertIsNone(L.ctxs["link"]["tunnel_endpoint"])
        for f in FIVE:
            self.assertFalse(L.engine.cfg.effective(f), f)

    def test_a_restart_picks_the_grant_up(self):
        """재료 확인 — 같은 파일로 다시 시작하면 켜진다(위 단언이 "파일이 틀려서" 헛통과하지 않음)."""
        L = Live(self, grant=False)
        L.grant_on_disk()
        L.restart()
        L.cycle()
        self.assertTrue(L.ctxs["wifi"]["allow_location"])


class TestTheRevokingCycleIsJudgedLikeARestart(unittest.TestCase):
    """QA-6: 철회로 넘어가는 주기의 판정은 "동의를 끄고 재시작" 경로와 같다(AC-3)."""

    def _sig(self, findings):
        return [(f.kind, f.severity, f.attribution) for f in findings]

    def test_same_findings(self):
        live = Live(self)
        live.cycle()
        live.revoke("location")
        live.world = obs(ssid=SSID, bssid=BSSID, gw_mac=GW_MAC_ALT)
        _, a = live.cycle()

        rs = Live(self)
        rs.cycle()
        rs.revoke("location")
        rs.restart()
        rs.world = obs(ssid=SSID, bssid=BSSID, gw_mac=GW_MAC_ALT)
        _, b = rs.cycle()

        self.assertEqual(self._sig(a), self._sig(b))
        gw = [f for f in a if f.kind == "GW_MAC_CHANGED"]
        self.assertTrue(gw)
        self.assertEqual({(f.severity, f.attribution) for f in gw}, {("low", "network_change")})


class TestRestartPathIsUnchanged(unittest.TestCase):
    """QA-10: 동의를 끄고 재시작하는 경로의 판정은 기준 커밋과 같다 — 귀속 `network_change`, 게이트웨이 MAC 변화 low, 기준선 초기화, 열린 조사 닫힘.
    링크 없는 주기의 `network`(Q3 로 바뀌는 것)는 여기서 보지 않는다."""

    def test_restarting_with_the_consent_off(self):
        L = Live(self)
        L.cycle()                       # 스냅샷 저장 — 앵커의 게이트웨이 MAC 은 GW_MAC
        L.cycle()
        L.world = obs(ssid=SSID, bssid=BSSID, gw_mac=GW_MAC_ALT)
        _, f = L.cycle()                # 같은 네트워크의 MAC 변화 — high, 조사가 열린다
        self.assertIn(("GW_MAC_CHANGED", "high", None), [(x.kind, x.severity, x.attribution) for x in f])
        self.assertIn("INVESTIGATION_OPENED", [x.kind for x in f])
        L.revoke("location")
        L.restart()                     # 되살린 앵커는 GW_MAC(60초 저장이 아직 안 돌아옴)
        _, f = L.cycle()
        sig = [(x.kind, x.severity, x.attribution) for x in f]
        self.assertIn(("GW_MAC_CHANGED", "low", "network_change"), sig)
        self.assertIn("INVESTIGATION_ABANDONED", [x.kind for x in f])
        self.assertEqual(L.engine.state.get("cycles_on_network"), 1, "기준선이 지워져 1 부터 센다")


class TestKeepingConsentIsUnchanged(unittest.TestCase):
    """QA-7: 철회가 없으면 지금과 같다 — 설정 파일을 그대로 두고 여러 주기를 돌아도 동의는 그대로다(기준 커밋에서도 통과)."""

    def test_nothing_changes_without_a_revoke(self):
        L = Live(self)
        for _ in range(5):
            o, _ = L.cycle()
        self.assertEqual(_wifi_ident(o.data["wifi"]), (SSID, BSSID))
        self.assertEqual(L.ctxs["link"]["tunnel_endpoint"], ENDPOINT)
        for f in FIVE:
            self.assertTrue(L.engine.cfg.effective(f), f)


class TestUnreadableConfigFilesWhileRunning(unittest.TestCase):
    """ADV-1(b): 실행 중에 설정 파일을 못 읽게 된 주기는 직전 값을 쓴다(Q2). 온전한 파일에서 항목이 없으면 철회다."""
    def test_a_bad_file_while_running_keeps_the_previous_consent(self):
        for name, content in UNREADABLE:
            with self.subTest(name):
                L = Live(self)
                L.cycle()
                L.write_raw(content)
                o, _ = L.cycle()
                o, _ = L.cycle()
                self.assertTrue(L.ctxs["wifi"]["allow_location"])
                self.assertEqual(_wifi_ident(o.data["wifi"]), (SSID, BSSID))
                self.assertEqual(L.ctxs["link"]["tunnel_endpoint"], ENDPOINT)

    def test_a_well_formed_file_without_the_consent_is_a_revoke(self):
        """객체로 온전히 읽혔고 그 동의 항목이 없으면 철회다(SPEC AC-2)."""
        for content in (b"{}", b'{"consents": {}}', b'{"consents": {"location": {"granted": false}}}'):
            with self.subTest(content):
                L = Live(self)
                L.cycle()
                L.write_raw(content)
                o, _ = L.cycle()
                self.assertFalse(L.ctxs["wifi"]["allow_location"])
                self.assertEqual(_wifi_ident(o.data["wifi"]), (None, None))


class TestInterleavings(unittest.TestCase):
    """ADV-2: 철회·못 읽음·다시 동의가 엇갈려도 메모리의 동의는 "시작 값과 지금까지 온전히 읽은 값 모두의 최소" 다."""

    def _apply(self, L, step):
        if step in ("G", "R") and (os.path.isdir(L.path)
                                   or (os.path.exists(L.path) and not os.access(L.path, os.R_OK))):
            # CLI 는 디렉터리·읽을 수 없는 파일 위에 저장하지 못한다 — 사람이 그 자리를 치운 뒤 다시 쓴 것으로 본다.
            L.write_raw(None)
        if step == "G":
            L.grant_on_disk()
        elif step == "R":
            L.revoke("location")
        else:
            L.write_raw(dict(UNREADABLE)[step])

    def test_fixed_sequences(self):
        for seq, expect in ((("R", "잘린 JSON", "G", "빈 파일"), False),
                            (("잘린 JSON", "R"), False),
                            (("G", "granted 문자열 true", "G"), True),
                            (("granted 문자열 false",), True)):
            with self.subTest(seq):
                L = Live(self)
                L.cycle()
                for s in seq:
                    self._apply(L, s)
                    L.cycle()
                self.assertEqual(L.ctxs["wifi"]["allow_location"], expect)

    def test_random_sequences(self):
        rng = random.Random(20261123)
        names = [n for n, _ in UNREADABLE]
        L = Live(self)
        L.cycle()
        mem = True
        for i in range(200):
            s = rng.choice(["G", "R"] + names)
            self._apply(L, s)
            if s == "R":
                mem = False
            o, _ = L.cycle()
            self.assertEqual(L.ctxs["wifi"]["allow_location"], mem, (i, s))
            self.assertEqual(_wifi_ident(o.data["wifi"])[0] is not None, mem, (i, s))


class TestOneCycleOneView(unittest.TestCase):
    """ADV-4: 한 주기 안에서는 수집과 판정이 같은 동의 값을 본다 — 주기 도중 파일이 바뀌어도 다음 주기부터."""

    def test_a_revoke_during_observe_waits_for_the_next_cycle(self):
        L = Live(self)
        L.cycle()
        L.during_observe = lambda: L.revoke("location")
        o, _ = L.cycle()
        self.assertTrue(L.ctxs["wifi"]["allow_location"])
        self.assertEqual(_wifi_ident(o.data["wifi"])[0], SSID)
        self.assertEqual(L.engine.identity_ssid, SSID, "같은 주기의 판정도 동의가 있던 값으로 — 수집과 판정이 엇갈리지 않음")
        o, _ = L.cycle()
        self.assertEqual(_wifi_ident(o.data["wifi"]), (None, None))
        self.assertIsNone(L.engine.identity_ssid)


class TestLinklessCyclesAfterTheConsentIsOff(unittest.TestCase):
    """QA-5: 동의가 꺼진 뒤 링크 없는 주기의 `network` 는 비운다(Q3) — 실행 중 철회, 재시작 경로 모두."""

    def _check_blank(self, L, findings):
        kinds = [f.kind for f in findings]
        self.assertIn("LINK_ABSENT", kinds)
        for f in findings:
            self.assertIsNone(f.network, f.kind)
        self.assertIsNone(L.state_on_disk().get("network"))

    def test_revoking_then_losing_the_link(self):
        L = Live(self)
        L.vpn = vpn_state("connected", provider="macos")
        L.cycle()
        L.revoke("location")
        L.link_up = False
        # 링크가 없는 주기에 VPN 도 끊긴다 — 링크 없는 주기의 VPN 판정(`vpn_detect.without_link`)이 나야 그 `network` 를 본다.
        L.vpn = vpn_state("disconnected", reason=ENDPOINT_REASON, provider="macos")
        before = L.lines()
        _, findings = L.cycle(step=60.0)   # 공백도 함께 — MEASUREMENT_GAP 의 network 도 본다
        self.assertIn("MEASUREMENT_GAP", [f.kind for f in findings])
        self.assertTrue(any(f.kind.startswith("VPN_") for f in findings), "링크 없는 주기의 VPN 판정도 본다")
        self._check_blank(L, findings)
        for line in L.new_lines(before):
            self.assertNotIn(SSID, line)
        L.link_up = True
        L.cycle()
        self.assertEqual(_ssid_part(L.state_on_disk().get("network")), "-", "다음 완전한 주기가 관측 키로 채운다")

    def test_restarting_with_the_consent_off_then_losing_the_link(self):
        L = Live(self)
        L.cycle()
        self.assertEqual(_ssid_part(L.state_on_disk().get("network")), SSID)
        L.revoke("location")
        L.restart()
        L.link_up = False
        _, findings = L.cycle()
        self._check_blank(L, findings)

    def test_an_install_that_never_consented_keeps_its_key(self):
        """처음부터 동의가 없던 설치는 SSID 자리가 이미 "-" 다 — 지금처럼 그 키를 쓴다(기준 커밋에서도 통과)."""
        L = Live(self, grant=False)
        L.cycle()
        key = L.state_on_disk().get("network")
        self.assertEqual(_ssid_part(key), "-")
        L.link_up = False
        _, findings = L.cycle()
        absent = [f for f in findings if f.kind == "LINK_ABSENT"]
        self.assertEqual([f.network for f in absent], [key])
        self.assertEqual(L.state_on_disk().get("network"), key)

    def test_a_consented_install_keeps_its_key(self):
        """동의가 켜진 채 링크가 끊기면 지금처럼 SSID 를 품은 키 그대로다(기준 커밋에서도 통과)."""
        L = Live(self)
        L.cycle()
        key = L.state_on_disk().get("network")
        L.link_up = False
        _, findings = L.cycle()
        self.assertEqual([f.network for f in findings if f.kind == "LINK_ABSENT"], [key])


class TestKeyParsing(unittest.TestCase):
    """ADV-3: SSID 자리를 읽는 규칙 — SSID 에 `|` 가 있어도, 상태 값이 문자열이 아니어도."""

    def test_keys(self):
        from netmon.detect import network_without_ssid
        for key, keep in (("en0|-|192.0.2.0/24", True), ("en0|-|-", True),
                          ("en0|ExampleNet|192.0.2.0/24", False), ("en0|a|b|192.0.2.0/24", False),
                          ("en0|-|x|-", False), ("en0||192.0.2.0/24", False), ("en0|||-", False),
                          ("en0|", False), ("garbage", False), (5, False), (["en0|-|-"], False),
                          ({"k": 1}, False)):
            with self.subTest(key):
                self.assertEqual(network_without_ssid(key), key if keep else None)
        self.assertIsNone(network_without_ssid(None))

    def test_a_ssid_with_separators_is_still_blanked(self):
        L = Live(self)
        L.world = obs(ssid="a|-|b", bssid=BSSID)
        L.cycle()
        L.revoke("location")
        L.link_up = False
        _, findings = L.cycle()
        for f in findings:
            self.assertIsNone(f.network, f.kind)


class TestCliWording(unittest.TestCase):
    """QA-8: CLI 가 적용 시점을 사실대로 말한다."""

    def test_revoke_says_next_cycle_and_the_file(self):
        L = Live(self)
        out = L.revoke("location")
        self.assertIn("다음 측정 주기", out)
        self.assertIn(L.path, out)

    def test_revoke_says_recorded_values_stay(self):
        L = Live(self)
        self.assertIn("이미 기록된 값은 지우지 않습니다", L.revoke("location"))

    def test_grant_says_restart(self):
        L = Live(self, grant=False)
        rc, out = _cli("--config", L.path, "consent", "grant", "location")
        self.assertEqual(rc, 0)
        self.assertIn("netmon service restart", out)
        self.assertIn("다시 시작", out)

    def test_consent_list_marks_unimplemented_checks(self):
        L = Live(self, grant=False)
        rc, out = _cli("--config", L.path, "consent", "list")
        self.assertEqual(rc, 0)
        enables = [line for line in out.splitlines() if line.strip().startswith("켜지는 것")]
        ext = [line for line in enables if "vpn.tunnel_probe" in line]
        self.assertEqual(len(ext), 1)
        for feat in ("detect.dns_intercept", "detect.tls_intercept", "detect.public_ip"):
            seg = ext[0].split(feat, 1)[1].split(",", 1)[0]
            self.assertIn("예정", seg, feat)
        self.assertNotIn("예정", ext[0].split("vpn.tunnel_probe", 1)[1].split(",", 1)[0])

    def test_consent_text_does_not_claim_the_checks_run(self):
        ext = configmod.CONSENTS["external_probes"]
        for field in ("why", "sends_out"):
            self.assertIn("예정", ext[field], field)
        # 목적 문장이 지금 동작하는 터널 엔드포인트 측정으로 시작한다 — 구현 전 점검을 먼저 말하지 않는다.
        self.assertTrue(ext["why"].startswith("VPN"))
        self.assertIn("ICMP 뿐", ext["sends_out"])

    def test_wizard_text_does_not_claim_the_checks_run(self):
        from netmon import messages
        for lang, word in (("ko", "예정"), ("en", "planned")):
            head = messages.get("WZ_EXTERNAL_HEAD", lang)
            body = messages.get("WZ_EXTERNAL_BODY", lang)
            row = messages.get("WZ_ROW_EXTERNAL", lang)
            self.assertIn(word, head + body, lang)
            self.assertIn(word, row, lang)


class TestConfigObjectShapes(unittest.TestCase):
    """메모리의 `Config` 가 모양이 틀린 데이터를 품어도 예외 없이 "동의 없음·기능 기본값" 으로 읽는다(DEV-1 검수 [낮음] — `load` 를 거치지
    않고 만든 설정. 지금은 `load` 가 먼저 고쳐 두므로 이 방어만으로 지켜지는 경로는 없다)."""

    def _cfg(self, data):
        return configmod.Config(path="/nonexistent/config.json", data=data)

    def test_granted_must_be_boolean_true(self):
        for value in ("false", "true", 1, 0, None, [], {}):
            with self.subTest(value):
                self.assertFalse(self._cfg({"consents": {"location": {"granted": value}}}).consented("location"))
        self.assertTrue(self._cfg({"consents": {"location": {"granted": True}}}).consented("location"))

    def test_bad_containers_mean_no_consent(self):
        for consents in (None, [], "x", 5, {"location": True}, {"location": "yes"}, {"location": None}):
            with self.subTest(consents):
                self.assertFalse(self._cfg({"consents": consents}).consented("location"))

    def test_bad_features_mean_defaults(self):
        for feats in (None, [], "x", 5):
            with self.subTest(feats):
                cfg = self._cfg({"features": feats, "consents": {"location": {"granted": True}}})
                self.assertFalse(cfg.feature("detect.evil_twin"))
                self.assertTrue(cfg.feature("detect.wifi"), "기본으로 켜지는 기능은 기본값 그대로")
                self.assertFalse(cfg.effective("detect.evil_twin"))


if __name__ == "__main__":
    unittest.main()
