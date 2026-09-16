"""Wi-Fi 암호화 강도와 위치 헬퍼 출력 해석.

암호화 강도 표는 실측에서 깨졌다. `NONE` 만 보고 만든 고정 문자열 표가
다른 네트워크에서 나온 `WPA2_PSK` 를 읽지 못해 다운그레이드 판정이 조용히
멈췄다. 표기를 토큰으로 읽도록 고쳤고 이 파일이 그 회귀를 막는다.
"""
from __future__ import annotations

import unittest

from netmon import wifi_helper
from netmon.detect.wifi import rank


class TestSecurityRank(unittest.TestCase):
    def test_real_macos_strings(self):
        """실제로 macOS 가 돌려준 표기."""
        self.assertEqual(rank("NONE"), 0)
        self.assertEqual(rank("WPA2_PSK"), 3)

    def test_spelling_variants_agree(self):
        self.assertEqual(rank("WPA2_PSK"), rank("WPA2 Personal"))
        self.assertEqual(rank("WPA3_PSK"), rank("WPA3 Personal"))

    def test_ordering(self):
        self.assertLess(rank("Open"), rank("WEP"))
        self.assertLess(rank("WEP"), rank("WPA_PSK"))
        self.assertLess(rank("WPA_PSK"), rank("WPA2_PSK"))
        self.assertLess(rank("WPA2_PSK"), rank("WPA2 Enterprise"))
        self.assertLess(rank("WPA2 Enterprise"), rank("WPA3_PSK"))

    def test_mixed_mode_counts_as_the_weaker_half(self):
        """WPA2/WPA3 혼합은 WPA2 접속을 허용하므로 WPA2 로 친다."""
        self.assertEqual(rank("WPA2/WPA3 Personal"), rank("WPA2 Personal"))
        self.assertLess(rank("WPA2/WPA3 Personal"), rank("WPA3 Personal"))

    def test_wpa3_does_not_match_as_wpa(self):
        """'wpa3' 안에 'wpa' 가 들어 있어 부분 일치로 약하게 읽히면 안 된다."""
        self.assertEqual(rank("WPA3_PSK"), 5)

    def test_unknown_spelling_is_none_not_a_guess(self):
        self.assertIsNone(rank("ZZZ-Unknown"))
        self.assertIsNone(rank(""))
        self.assertIsNone(rank(None))


class TestHelperOutput(unittest.TestCase):
    def test_wifi_values(self):
        d = wifi_helper.parse_output("ssid=ExampleNet\nbssid=00:00:5e:00:53:aa\n")
        self.assertEqual(d["ssid"], "ExampleNet")
        self.assertEqual(d["bssid"], "00:00:5e:00:53:aa")

    def test_status(self):
        self.assertEqual(wifi_helper.parse_output("status=authorized-always\n"),
                         {"status": "authorized-always"})

    def test_empty_values_survive_parsing(self):
        """권한이 없으면 헬퍼가 빈 값을 준다. 키는 있고 값만 비는 형태다."""
        d = wifi_helper.parse_output("ssid=\nbssid=\n")
        self.assertEqual(d, {"ssid": "", "bssid": ""})

    def test_garbage_is_ignored(self):
        self.assertEqual(wifi_helper.parse_output("쓰레기\n\n"), {})


if __name__ == "__main__":
    unittest.main()
