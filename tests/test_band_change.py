"""밴드 전환이 "로밍" 으로만 기록되던 문제.

2026-09-17 10:58:15 실측: 맥이 5GHz 에서 2.4GHz 로 내려갔는데 netmon 은
`WIFI_ROAM`("같은 SSID 안에서 접속점 변경됨") 하나만 남겼다. 전송률 상한이
1200 에서 144 Mbps 로 떨어진 채 몇 시간이 지났고, 그 뒤 끊김이 반복됐다.

로밍과 밴드 전환은 의미가 다르다 — 속도 상한이 통째로 달라진다.
값은 전부 문서용 대역이다.
"""
from __future__ import annotations

import unittest

from netmon import messages as msg
from netmon.collect.wifi import radio_from
from netmon.detect import Context, network_key, run_all
from tests.helpers import BSSID, BSSID_ALT, GW_MAC_ALT, SSID, by_kind, kinds, obs

ON = {k: True for k in ("detect.l2", "detect.dhcp", "detect.dns", "detect.route",
                        "detect.wifi", "detect.quality", "detect.vpn", "detect.evil_twin")}


def _ctx(cur):
    return Context(elapsed=5.0, interval=5.0, features=ON, state={"icmp_gw": True},
                   attributions=[], network=network_key(cur))


class TestRadioParsing(unittest.TestCase):
    def test_reads_helper_fields(self):
        got = radio_from({"channel": "36", "band": "5", "width": "80",
                          "rssi": "-36", "noise": "-96", "txrate": "1080"})
        self.assertEqual(got, {"channel": 36, "width": 80, "rssi": -36,
                               "noise": -96, "txrate": 1080, "band": "5", "snr": 60})

    def test_missing_fields_are_omitted_not_guessed(self):
        self.assertEqual(radio_from({"band": "2.4"}), {"band": "2.4"})

    def test_garbage_is_skipped(self):
        self.assertEqual(radio_from({"channel": "없음", "band": "5"}), {"band": "5"})

    def test_snr_needs_both_halves(self):
        self.assertNotIn("snr", radio_from({"rssi": "-36"}))


class TestBandChange(unittest.TestCase):
    def _pair(self, pb, cb, prate=None, crate=None, gw=None):
        prev = obs(ssid=SSID, bssid=BSSID, band=pb, channel=36, txrate=prate)
        cur = obs(ssid=SSID, bssid=BSSID_ALT, band=cb, channel=6, txrate=crate,
                  **({"gw_mac": gw} if gw else {}))
        return run_all(prev, cur, _ctx(cur))

    def test_dropping_to_24_is_reported(self):
        f = by_kind(self._pair("5", "2.4"), "WIFI_BAND_CHANGED")
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, "medium", "낮은 대역으로 내려간 것이 손해다")

    def test_rate_ceiling_is_named_when_known(self):
        f = by_kind(self._pair("5", "2.4", 1200, 144), "WIFI_BAND_CHANGED")
        self.assertEqual(f.summary, msg.WIFI_BAND_CHANGED_RATE % ("5", "2.4", 1200, 144))

    def test_moving_up_is_only_info(self):
        self.assertEqual(by_kind(self._pair("2.4", "5"), "WIFI_BAND_CHANGED").severity, "info")

    def test_it_is_not_also_called_roaming(self):
        # 이것이 핵심이다. 예전에는 WIFI_ROAM 하나만 남았다.
        self.assertNotIn("WIFI_ROAM", kinds(self._pair("5", "2.4")))

    def test_same_band_roam_is_still_roaming(self):
        self.assertIn("WIFI_ROAM", kinds(self._pair("5", "5")))
        self.assertNotIn("WIFI_BAND_CHANGED", kinds(self._pair("5", "5")))

    def test_evil_twin_still_wins_over_band_change(self):
        # 게이트웨이까지 바뀌었으면 밴드 전환이라고 넘어가면 안 된다.
        found = self._pair("5", "2.4", gw=GW_MAC_ALT)
        self.assertIn("EVIL_TWIN_CANDIDATE", kinds(found))
        self.assertIn("WIFI_BAND_CHANGED", kinds(found))

    def test_no_band_data_falls_back_to_roaming(self):
        # 위치 권한이 없으면 대역도 못 읽는다. 예전 동작을 유지한다.
        self.assertIn("WIFI_ROAM", kinds(self._pair(None, None)))


if __name__ == "__main__":
    unittest.main()
