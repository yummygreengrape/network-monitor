"""보존 정리와 로그 회전.

디스크를 지키는 약속이고, 실전에서는 UTC 자정과 5MB 초과에서만 돌아서
몇 달을 켜 두기 전까지 한 번도 실행되지 않는다. 그동안 조용히 고장 나 있으면
알아챌 방법이 없다.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
import unittest

from netmon.model import Observation
from netmon.store import Store


class TestPrune(unittest.TestCase):
    def _day(self, days_ago):
        import datetime
        return (datetime.datetime.now(datetime.timezone.utc)
                - datetime.timedelta(days=days_ago)).strftime("%Y-%m-%d")

    def _aged(self, d, name, days_old, body="{}\n"):
        """파일을 만들고 mtime 도 과거로 돌린다.

        정리는 **파일 이름의 날짜**로 판단해야 한다. mtime 을 일부러 어긋나게
        두어, mtime 에 기대는 구현이면 테스트가 깨지게 한다.
        """
        p = os.path.join(d, name)
        with open(p, "w") as fh:
            fh.write(body)
        os.utime(p, (time.time(), time.time()))   # mtime 은 '지금'
        return p

    def test_old_records_are_removed_and_recent_kept(self):
        with tempfile.TemporaryDirectory() as d:
            s = Store(d)
            old = self._aged(d, "samples-%s.jsonl" % self._day(20), 20)
            mid = self._aged(d, "samples-%s.jsonl" % self._day(10), 10)
            new = self._aged(d, "samples-%s.jsonl" % self._day(0), 0)
            removed = s.prune(14)
            self.assertEqual(removed, 1)
            self.assertFalse(os.path.exists(old))
            self.assertTrue(os.path.exists(mid))
            self.assertTrue(os.path.exists(new))

    def test_it_only_touches_record_files(self):
        """설정·솔트·에이전트 로그를 지우면 안 된다."""
        with tempfile.TemporaryDirectory() as d:
            s = Store(d)
            keep = [self._aged(d, n, 99) for n in
                    ("state.json", "salt", "agent.out.log", "config.json")]
            self._aged(d, "events-2020-01-01.jsonl", 99)
            s.prune(14)
            for p in keep:
                self.assertTrue(os.path.exists(p), "%s 를 지웠다" % os.path.basename(p))

    def test_zero_retention_does_not_wipe_today(self):
        """보존 0일을 넣어도 방금 쓴 기록이 사라지면 안 된다."""
        with tempfile.TemporaryDirectory() as d:
            s = Store(d)
            today = self._day(0)
            s.write_sample(Observation(ts="%sT10:00:00Z" % today, data={"x": 1}))
            s.prune(0)
            self.assertEqual(len(list(s.samples(today))), 1,
                             "보존 0일이 오늘 기록을 지우면 안 된다")

    def test_a_missing_directory_does_not_raise(self):
        with tempfile.TemporaryDirectory() as d:
            s = Store(os.path.join(d, "sub"))
            self.assertEqual(s.prune(14), 0)


    def test_mtime_is_not_the_basis(self):
        """백업·동기화가 mtime 을 건드려도 오래된 기록은 오래된 것이다."""
        with tempfile.TemporaryDirectory() as d:
            s = Store(d)
            stale = self._aged(d, "samples-%s.jsonl" % self._day(30), 30)
            os.utime(stale, (time.time(), time.time()))   # 방금 만진 것처럼
            self.assertEqual(s.prune(14), 1)
            self.assertFalse(os.path.exists(stale))


class TestAgentLogRotation(unittest.TestCase):

    def _day(self, days_ago):
        import datetime
        return (datetime.datetime.now(datetime.timezone.utc)
                - datetime.timedelta(days=days_ago)).strftime("%Y-%m-%d")
    """launchd 의 출력 파일은 회전되지 않는다. 몇 달 켜 두면 수 GB 가 된다."""

    def test_a_large_log_is_trimmed_keeping_the_tail(self):
        with tempfile.TemporaryDirectory() as d:
            s = Store(d)
            p = os.path.join(d, "agent.out.log")
            with open(p, "w", encoding="utf-8") as fh:
                for i in range(400000):
                    fh.write("줄 %d 내용\n" % i)
            before = os.path.getsize(p)
            self.assertGreater(before, Store.AGENT_LOG_MAX)

            self.assertEqual(s.rotate_agent_logs(), 1)
            after = os.path.getsize(p)
            self.assertLess(after, before)
            with open(p, encoding="utf-8") as fh:
                lines = fh.readlines()
            self.assertIn("잘랐다", lines[0])
            self.assertEqual(lines[-1].strip(), "줄 399999 내용",
                             "최근 내용이 남아야 한다")

    def test_a_small_log_is_left_alone(self):
        with tempfile.TemporaryDirectory() as d:
            s = Store(d)
            p = os.path.join(d, "agent.err.log")
            open(p, "w").write("짧은 내용\n")
            self.assertEqual(s.rotate_agent_logs(), 0)
            with open(p, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "짧은 내용\n")

    def test_record_files_are_not_rotated(self):
        """기록은 보존 기간으로 관리한다. 중간을 잘라 내면 JSON 이 깨진다."""
        with tempfile.TemporaryDirectory() as d:
            s = Store(d)
            p = os.path.join(d, "samples-%s.jsonl" % self._day(0))
            with open(p, "w") as fh:
                fh.write(("%s\n" % json.dumps({"ts": "2026-09-16T00:00:00Z"})) * 200000)
            size = os.path.getsize(p)
            s.rotate_agent_logs()
            self.assertEqual(os.path.getsize(p), size)

    def test_prune_also_rotates(self):
        """하루에 한 번 도는 정리에 회전이 딸려 있다."""
        with tempfile.TemporaryDirectory() as d:
            s = Store(d)
            p = os.path.join(d, "agent.out.log")
            with open(p, "w", encoding="utf-8") as fh:
                for i in range(400000):
                    fh.write("줄 %d\n" % i)
            s.prune(14)
            self.assertLess(os.path.getsize(p), Store.AGENT_LOG_MAX)


if __name__ == "__main__":
    unittest.main()
