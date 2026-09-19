"""터미널 로그의 시각을 현지 시각으로.

화면 머리의 시계는 현지 시각인데 판정 줄은 UTC 를 표시 없이 찍어서, KST
새벽 1시 32분 경보가 "16:32" 로 보였다.
"""
from __future__ import annotations

import os
import time
import unittest

from netmon.model import local_stamp


class TestLocalStamp(unittest.TestCase):
    def setUp(self):
        self._tz = os.environ.get("TZ")
        os.environ["TZ"] = "Asia/Seoul"
        time.tzset()

    def tearDown(self):
        if self._tz is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = self._tz
        time.tzset()

    def test_utc_record_is_shown_in_local_time_with_date(self):
        self.assertEqual(local_stamp("2026-09-19T16:32:56Z"), "09-20 01:32:56")

    def test_unreadable_value_falls_back(self):
        self.assertEqual(local_stamp("2026-09-19 16:32:56"), "16:32:56")
        self.assertEqual(local_stamp(""), "")


if __name__ == "__main__":
    unittest.main()
