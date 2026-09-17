"""재시작이 비교 기준을 버리던 문제.

`self.prev`/`self.anchor` 가 생성 시 None 이고 디스크에 관측이 저장되지
않아, 재시작 경계에 걸친 변화가 통째로 사라졌다. 게이트웨이 MAC 과 DHCP
서버가 동시에 바뀌어도 판정이 하나도 나지 않는 것을 실험으로 확인했다.
`first_sample` 귀속 이벤트가 0건이라 사후 감사로도 알 수 없었다.

launchd 가 KeepAlive 로 되살리므로 의도치 않은 재시작도 잦다.
값은 전부 문서용 대역이다.
"""
from __future__ import annotations

import tempfile
import unittest

from netmon import config as configmod
from netmon.engine import Engine
from netmon.store import Store
from tests.helpers import DHCP_SRV2, GW_MAC, GW_MAC_ALT, SSID, obs


def _engine(d):
    return Engine(configmod.load(), Store(d))


def _sec(findings):
    return [f.kind for f in findings if f.axis == "security"]


class TestBaselineSurvivesRestart(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.before = obs(ts="2026-01-01T00:00:00Z", ssid=SSID, gw_mac=GW_MAC)

    def _seed(self, observation=None, wall=1000.0):
        e = _engine(self.dir)
        o = observation or self.before
        e.judge(o, 0.0)
        e._keep_baseline(o, wall)
        e.store.save_state(e.state)
        return e

    def test_a_change_across_the_boundary_is_still_judged(self):
        self._seed()
        after = obs(ts="2026-01-01T00:00:05Z", ssid=SSID,
                    gw_mac=GW_MAC_ALT, dhcp_server=DHCP_SRV2)
        found = _sec(_engine(self.dir).judge(after, 5.0))
        self.assertIn("GW_MAC_CHANGED", found)
        self.assertIn("DHCP_SERVER_CHANGED", found)

    def test_baseline_is_restored(self):
        self._seed()
        e = _engine(self.dir)
        self.assertIsNotNone(e.prev)
        self.assertIsNotNone(e.anchor)
        self.assertEqual(e.prev.ts, self.before.ts)
        self.assertEqual(e.prev_wall, 1000.0)

    def test_unchanged_state_after_restart_is_silent(self):
        # 되살렸다고 해서 매 재시작마다 판정이 쏟아지면 안 된다.
        self._seed()
        same = obs(ts="2026-01-01T00:00:05Z", ssid=SSID, gw_mac=GW_MAC)
        self.assertEqual(_sec(_engine(self.dir).judge(same, 5.0)), [])

    def test_incomplete_observation_never_becomes_the_baseline(self):
        e = self._seed()
        gone = obs(ts="2026-01-01T00:00:05Z", ssid=None, gw_mac=None)
        gone.data["iface"]["primary"] = None
        e._keep_baseline(gone, 9999.0)     # 저장 주기를 넘겨도
        self.assertEqual(e.store.load_baseline()["ts"], self.before.ts,
                         "링크가 없던 주기를 기준으로 삼으면 안 된다")

    def test_baseline_is_not_rewritten_every_cycle(self):
        # state.json 에 넣으면 쓰기량이 20배가 된다. 60초 주기로 나눠 뒀다.
        e = self._seed()
        later = obs(ts="2026-01-01T00:00:05Z", ssid=SSID, gw_mac=GW_MAC)
        e._keep_baseline(later, 1005.0)                  # 5초 뒤 — 건너뜀
        self.assertEqual(e.store.load_baseline()["ts"], self.before.ts)
        e._keep_baseline(later, 1070.0)                  # 70초 뒤 — 기록
        self.assertEqual(e.store.load_baseline()["ts"], later.ts)

    def test_state_json_stays_small(self):
        e = self._seed()
        self.assertNotIn("last_obs", e.state)
        self.assertNotIn("last_obs_wall", e.state)

    def test_no_saved_state_starts_cold(self):
        e = _engine(tempfile.mkdtemp())
        self.assertIsNone(e.prev)

    def test_corrupt_saved_observation_does_not_crash(self):
        _engine(self.dir).store.save_baseline({"nonsense": True})
        self.assertIsNone(_engine(self.dir).prev)

    def test_unreadable_baseline_file_does_not_crash(self):
        with open(_engine(self.dir).store.baseline_path, "w") as fh:
            fh.write("{ 깨진 json")
        self.assertIsNone(_engine(self.dir).prev)

    def test_a_long_outage_still_reports_security_but_explains_quality(self):
        """에이전트가 오래 멈춰 있었어도 보안 변화는 판정된다.

        큰 elapsed 는 sleep 으로 귀속되는데, sleep 은 품질만 설명하고
        정체성 판정(identity_attribution)에는 들어가지 않는다.
        """
        self._seed()
        after = obs(ts="2026-01-01T03:00:00Z", ssid=SSID, gw_mac=GW_MAC_ALT)
        found = [f for f in _engine(self.dir).judge(after, 10800.0)
                 if f.kind == "GW_MAC_CHANGED"]
        self.assertEqual(len(found), 1)
        self.assertIsNone(found[0].attribution,
                          "멈춰 있던 동안의 게이트웨이 변경은 설명되지 않는다")


if __name__ == "__main__":
    unittest.main()
