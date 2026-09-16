"""실시간 화면. 순수 함수라 화면 없이 검증한다."""
from __future__ import annotations

import datetime
import re
import unittest

from netmon import watch
from netmon.investigate.model import Investigation

NOW = datetime.datetime(2026, 1, 1, 0, 1, 0, tzinfo=datetime.timezone.utc)


def plain(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def sample(ts="2026-01-01T00:00:57Z", **data):
    base = {
        "iface": {"primary": "en0", "primary_kind": "wifi"},
        "wifi": {"applicable": True, "security": "WPA2_PSK"},
        "dns": {"via_loopback": False},
    }
    base.update(data)
    return {"ts": ts, "data": base}


def event(kind="GW_MAC_CHANGED", axis="security", severity="high",
          ts="2026-01-01T00:00:50Z", attribution=None):
    return {"ts": ts, "kind": kind, "axis": axis, "severity": severity,
            "summary": "요약 문장", "attribution": attribution}


class TestRender(unittest.TestCase):
    def _render(self, **kw):
        args = dict(now=NOW, agent={"pid": "123", "installed": True},
                    last_sample=sample(), sample_count=10, events=[],
                    open_invs=[], rules_summary="기준 요약")
        args.update(kw)
        return plain(watch.render(**args))

    def test_shows_agent_running(self):
        self.assertIn("에이전트 실행 중 (pid 123)", self._render())

    def test_shows_not_installed(self):
        out = self._render(agent={"pid": None, "installed": False})
        self.assertIn("상시 실행 등록 안 됨", out)

    def test_marks_stale_data(self):
        """에이전트가 멈췄는데 오래된 화면을 그대로 보여 주면 안 된다."""
        fresh = self._render(last_sample=sample(ts="2026-01-01T00:00:57Z"))
        self.assertNotIn("갱신이 멈췄습니다", fresh)
        stale = self._render(last_sample=sample(ts="2026-01-01T00:00:00Z"),
                             stale_after=30.0)
        self.assertIn("갱신이 멈췄습니다", stale)

    def test_stale_threshold_follows_the_interval(self):
        """30초 간격으로 도는 에이전트를 60초마다 멈췄다고 하면 계속 거짓말이 된다."""
        old = sample(ts="2026-01-01T00:00:00Z")   # 60초 전
        self.assertIn("갱신이 멈췄습니다", self._render(last_sample=old, stale_after=30.0))
        self.assertNotIn("갱신이 멈췄습니다", self._render(last_sample=old, stale_after=120.0))

    def test_says_when_no_investigation_is_open(self):
        self.assertIn("열린 조사 없음", self._render())

    def test_shows_open_investigation_and_criteria_changes(self):
        inv = Investigation(id="l2-abc", kind="l2_identity",
                            trigger="GW_MAC_CHANGED",
                            opened_at="2026-01-01T00:00:00Z", network="n", cycles=7)
        inv.note("2026-01-01T00:00:10Z", "게이트웨이 MAC 이 또 바뀜")
        inv.retune("2026-01-01T00:00:20Z", "다른 신호가 겹쳤다", widened=True)
        out = self._render(open_invs=[inv])
        self.assertIn("l2_identity", out)
        self.assertIn("7주기", out)
        self.assertIn("기준 1번 바뀜", out)
        self.assertIn("다른 신호가 겹쳤다", out)

    def test_suppressed_findings_are_hidden_by_default(self):
        ev = [event(attribution="network_change")]
        self.assertIn("아직 판정 없음", self._render(events=ev))
        self.assertIn("GW_MAC_CHANGED", self._render(events=ev, show_suppressed=True))

    def test_long_summaries_are_cut_not_wrapped(self):
        ev = [event()]
        ev[0]["summary"] = "가" * 400
        out = self._render(events=ev)
        self.assertTrue(all(len(l) < 200 for l in out.splitlines()))
        self.assertIn("…", out)

    def test_vpn_states_are_shown(self):
        out = self._render(last_sample=sample(vpn={
            "warp": {"state": "disconnected"}, "tailscale": {"state": "connected"}}))
        self.assertIn("warp disconnected", out)
        self.assertIn("tailscale connected", out)

    def test_closing_the_window_does_not_stop_monitoring(self):
        self.assertIn("창을 닫아도 감시는 계속됩니다", self._render())


if __name__ == "__main__":
    unittest.main()
