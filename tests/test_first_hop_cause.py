"""첫 홉 무응답의 원인을 근거 없이 "무선 구간" 으로 단정하던 문제.

2026-09-20 15:37 실측: RSSI -33 dBm 에 대역 변화도 없는 상태에서 15초간
게이트웨이 응답이 빠졌는데 "무선 구간 문제로 추정" 이라고 적혔다. 유선 기계
(맥미니)에서 떴다면 문장 자체가 틀렸다. 이제 신호 세기가 근거일 때만 그렇게 말한다.
"""
from __future__ import annotations

import unittest

from netmon import messages as msg
from netmon.detect.quality import cause_note
from tests.helpers import obs


def _wifi(rssi=None, snr=None):
    o = obs()
    if rssi is not None:
        o.data["wifi"]["rssi"] = rssi
    if snr is not None:
        o.data["wifi"]["snr"] = snr
    return o


class TestCauseNote(unittest.TestCase):
    def test_strong_signal_does_not_blame_the_radio(self):
        self.assertEqual(cause_note(_wifi(-33, 60)), msg.FIRST_HOP_CAUSE_STRONG % -33)

    def test_weak_rssi_does(self):
        self.assertEqual(cause_note(_wifi(-80, 25)), msg.FIRST_HOP_CAUSE_WEAK % -80)

    def test_poor_snr_does_even_with_ok_rssi(self):
        self.assertEqual(cause_note(_wifi(-60, 15)), msg.FIRST_HOP_CAUSE_WEAK % -60)

    def test_wired_never_says_wireless(self):
        o = obs(iface_kind="ethernet")
        self.assertEqual(cause_note(o), msg.FIRST_HOP_CAUSE_WIRED)

    def test_unknown_signal_says_so(self):
        self.assertEqual(cause_note(_wifi()), msg.FIRST_HOP_CAUSE_UNKNOWN)

    def test_no_message_blames_wireless_without_evidence(self):
        for text in (msg.FIRST_HOP_CAUSE_STRONG, msg.FIRST_HOP_CAUSE_WIRED,
                     msg.FIRST_HOP_CAUSE_UNKNOWN, msg.WHY_LINK,
                     msg.INV_VPN_LEG_LINK, msg.INV_VPN_VERDICT_LINK):
            self.assertNotIn("무선 구간", text)


if __name__ == "__main__":
    unittest.main()
