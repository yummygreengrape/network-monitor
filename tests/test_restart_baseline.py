"""재시작이 비교 기준을 버리던 문제.

`self.prev`/`self.anchor` 가 생성 시 None 이고 디스크에 관측이 저장되지
않아, 재시작 경계에 걸친 변화가 통째로 사라졌다. 게이트웨이 MAC 과 DHCP
서버가 동시에 바뀌어도 판정이 하나도 나지 않는 것을 실험으로 확인했다.
`first_sample` 귀속 이벤트가 0건이라 사후 감사로도 알 수 없었다.

launchd 가 KeepAlive 로 되살리므로 의도치 않은 재시작도 잦다.
값은 전부 문서용 대역이다.
"""
from __future__ import annotations

import os
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


class TestTheLastReadSsidSurvivesARestartWithItsAnchor(unittest.TestCase):
    """마지막으로 읽은 SSID 는 기준선 스냅샷에 앵커와 같은 시점으로 남는다(작업 2026-09-27-ssid-gap-network-change, AC-5).

    state.json 은 매 주기, 스냅샷(baseline.json)은 60초마다 저장된다. 읽은 SSID 를 state.json 에 두면 재시작 뒤 앵커(옛 네트워크)와
    읽은 SSID(새 네트워크)가 어긋나, 같은 서브넷에서 SSID 만 바뀐 이동이 "같은 네트워크" 로 읽혀 high 가 된다(PLAN 검수 [높음]).
    설정은 임시 경로에 동의를 명시한다 — 위 `_engine` 은 기계의 사용자 설정을 읽는다.
    """

    def setUp(self):
        import os
        import shutil
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.cfg = configmod.load(os.path.join(self.dir, "config.json"))
        self.cfg.set_feature("detect.evil_twin", True)
        self.cfg.grant("location")

    def engine(self):
        return Engine(self.cfg, Store(self.dir))

    @staticmethod
    def gap(**kw):
        o = obs(ssid=None, **kw)
        o.data["wifi"]["helper_unavailable"] = True
        return o

    def test_a_restart_inside_a_gap_keeps_the_ssid(self):
        """(j) 복원 앵커가 공백 관측이어도 스냅샷의 읽은 SSID 로 이어받는다 — 공백 뒤 같은 SSID 는 이동이 아니다."""
        e = self.engine()
        e.judge(obs(ts="2026-01-01T00:00:00Z", ssid=SSID), 0.0)
        e.prev = e.anchor
        g = self.gap(ts="2026-01-01T00:00:05Z")
        e.judge(g, 5.0)
        e._keep_baseline(g, 1000.0)
        e.store.save_state(e.state)
        e2 = self.engine()
        self.assertEqual(e2.identity_ssid, SSID)
        cycles = e2.state.get("cycles_on_network")
        e2.judge(obs(ts="2026-01-01T00:00:10Z", ssid=SSID), 5.0)
        self.assertGreater(e2.state.get("cycles_on_network"), cycles, "이동으로 읽었다면 기준선이 지워져 1 부터 센다")

    def test_a_move_after_the_last_snapshot_is_still_a_move_after_a_restart(self):
        """앵커 저장 뒤 같은 서브넷·다른 SSID 로 옮기고 60초 안에 재시작 — 기준 커밋과 같은 등급(low, network_change). 읽은 SSID 가
        state.json 에 있었다면 새 SSID 가 되살아나 high 가 된다."""
        e = self.engine()
        a = obs(ts="2026-01-01T00:00:00Z", ssid=SSID, gw_mac=GW_MAC)
        e.judge(a, 0.0)
        e._keep_baseline(a, 1000.0)
        e.prev = a
        b = obs(ts="2026-01-01T00:00:05Z", ssid="OtherNet", gw_mac=GW_MAC_ALT)
        e.judge(b, 5.0)
        e._keep_baseline(b, 1005.0)          # 60초가 안 지나 저장하지 않는다
        e.store.save_state(e.state)
        e2 = self.engine()
        f = [x for x in e2.judge(obs(ts="2026-01-01T00:00:10Z", ssid="OtherNet", gw_mac=GW_MAC_ALT), 5.0)
             if x.kind == "GW_MAC_CHANGED"]
        self.assertEqual([(x.severity, x.attribution) for x in f], [("low", "network_change")])

    def test_a_broken_or_old_snapshot_falls_back_to_the_anchor(self):
        """ADV-1 스냅샷 키가 없거나 깨졌으면 되살린 관측이 읽은 SSID(공백 관측이면 없음)로 — 예외 없음. 상한 128자는 받고 129자는 버린다."""
        from netmon.engine import IDENTITY_SSID_MAX
        self.assertEqual(IDENTITY_SSID_MAX, 128)
        cases = [("키 없음", None, False), ("숫자", 5, False), ("목록", ["x"], False), ("빈 값", "", False),
                 ("상한", "a" * 128, True), ("상한+1", "a" * 129, False), ("제어 문자", "a\nb", True), ("구분자", "a|b", True),
                 ("짝 없는 대리 문자", "\ud800", False)]
        for name, value, kept in cases:
            with self.subTest(name):
                store = Store(self.dir)
                snap = {"ts": "2026-01-01T00:00:05Z", "data": self.gap(ts="2026-01-01T00:00:05Z").data, "wall": 1000.0}
                if name != "키 없음":
                    snap["identity_ssid"] = value
                self.write_raw(store, snap)
                self.assertEqual(self.engine().identity_ssid, value if kept else None)
        store = Store(self.dir)
        read = obs(ts="2026-01-01T00:00:05Z", ssid=SSID)
        store.save_baseline({"ts": read.ts, "data": read.data, "wall": 1000.0})
        self.assertEqual(self.engine().identity_ssid, SSID, "옛 스냅샷 — 앵커가 읽은 SSID(지금까지처럼 앵커와 견주는 것과 같음)")

    def test_an_unencodable_snapshot_value_does_not_stop_the_agent(self):
        """ADV-1 짝 없는 대리 문자는 되살리지 않는다 — 되살리면 다음 저장에서 UTF-8 예외로 에이전트가 죽고, 되살아나 같은 값을 다시 읽어
        되풀이한다(DEV-4 검수 1회차 [중간]). 저장이 예외 없이 되고 조작된 키가 사라진다(기준 커밋과 같음)."""
        store = Store(self.dir)
        g = self.gap(ts="2026-01-01T00:00:00Z")
        self.write_raw(store, {"ts": g.ts, "data": g.data, "wall": 1000.0, "identity_ssid": "\ud800"})
        e = self.engine()
        g2 = self.gap(ts="2026-01-01T00:00:05Z")
        e.judge(g2, 5.0)
        e._keep_baseline(g2, 1005.0)
        self.assertIsNone(Store(self.dir).load_baseline().get("identity_ssid"))

    @staticmethod
    def write_raw(store, snap):
        """사람이 고친 파일처럼 쓴다 — JSON 이스케이프(ensure_ascii)라 짝 없는 대리 문자도 `"\\ud800"` 로 들어간다."""
        import json
        with open(store.baseline_path, "w", encoding="utf-8") as fh:
            json.dump(snap, fh)

    def test_an_unwritable_anchor_ssid_is_not_restored_either(self):
        """ADV-1 대체값도 같은 검사를 거친다 — 키가 없거나 깨졌을 때 되살린 앵커의 SSID 가 짝 없는 대리 문자(원문·ident 로 감싼 것)이면
        되살리지 않는다. 되살리면 다음 저장에서 UTF-8 예외로 에이전트가 멈추고 되풀이한다(DEV-4 검수 2회차 [중간] — 기준 커밋에는 없던 경로).
        스냅샷의 `wifi` 가 목록·문자열이어도 엔진을 만드는 순간 죽지 않는다(2회차 [낮음])."""
        for name, wifi in (("원문", {"applicable": True, "ssid": "\ud800"}),
                           ("ident", {"applicable": True, "ssid": {"id": "ssid", "v": "\ud800"}}),
                           ("목록", ["x"]), ("문자열", "x")):
            for key in ("키 없음", 5):
                with self.subTest(wifi=name, key=key):
                    a = obs(ts="2026-01-01T00:00:00Z", ssid=SSID)
                    data = dict(a.data, wifi=wifi)
                    snap = {"ts": a.ts, "data": data, "wall": 1000.0}
                    if key != "키 없음":
                        snap["identity_ssid"] = key
                    self.write_raw(Store(self.dir), snap)
                    e = self.engine()
                    self.assertIsNone(e.identity_ssid)
                    if name in ("목록", "문자열"):
                        # 판정은 이 작업 전부터 그런 앵커에서 멈춘다(detect.link_restarted — 기준 커밋과 같음, NOTES 발견). 새 경로는 시작 단계뿐.
                        continue
                    g = self.gap(ts="2026-01-01T00:00:05Z")
                    e.judge(g, 5.0)
                    e._keep_baseline(g, 1005.0)
                    self.assertIsNone(Store(self.dir).load_baseline().get("identity_ssid"))

    def test_a_broken_key_falls_back_to_a_read_anchor(self):
        """깨진 키(키 없음만이 아니라)도 되살린 앵커가 SSID 를 읽은 관측이면 그 SSID 로 — 재시작 뒤 공백 → 같은 SSID 는 이동이 아니다
        (DEV-4 검수 2회차 [낮음]: 깨진 값 시험이 모두 공백 앵커라 "깨졌으면 None" 변이 M-k 가 살아남았다)."""
        for name, value in (("None", None), ("숫자", 5), ("목록", ["x"]), ("빈 값", ""), ("상한+1", "a" * 129), ("대리 문자", "\ud800")):
            with self.subTest(name):
                a = obs(ts="2026-01-01T00:00:00Z", ssid=SSID)
                self.write_raw(Store(self.dir), {"ts": a.ts, "data": a.data, "wall": 1000.0, "identity_ssid": value})
                e = self.engine()
                self.assertEqual(e.identity_ssid, SSID)
                e.judge(self.gap(ts="2026-01-01T00:00:05Z"), 5.0)
                e.prev = e.anchor
                cycles = e.state.get("cycles_on_network")
                e.judge(obs(ts="2026-01-01T00:00:10Z", ssid=SSID), 5.0)
                self.assertGreater(e.state.get("cycles_on_network"), cycles, "이동으로 읽었다면 기준선이 지워져 1 부터 센다")

    def run_cycles(self, e, seq):
        """`Engine.cycle` 을 그대로 돈다(관측만 바꿔 끼움) — 판정과 스냅샷 저장의 순서까지 실제 경로로."""
        out = []
        for wall, o in seq:
            e.observe = (lambda o=o: o)
            out.append(e.cycle(now=wall)[1])
        return out

    def test_the_snapshot_pairs_the_anchor_with_the_ssid_of_the_same_cycle(self):
        """(K-7) 저장은 판정 뒤다 — 앵커와 그 주기 갱신 뒤의 읽은 SSID 가 함께 저장된다. A 를 읽고 61초 뒤 같은 서브넷의 다른 SSID B 로
        옮겨(스냅샷 저장) 재시작한 뒤 B 에서 게이트웨이 MAC 이 바뀌면 같은 네트워크의 MAC 변화(high) — 기준 커밋과 같다. 저장을 판정 앞으로
        옮기면 B 앵커와 A 가 짝지어져 이동(low)으로 억제된다(DEV-4 검수 1회차 변이 X1)."""
        e = self.engine()
        self.run_cycles(e, [(1000.0, obs(ts="2026-01-01T00:00:00Z", ssid=SSID)),
                            (1061.0, obs(ts="2026-01-01T00:01:01Z", ssid="OtherNet"))])
        e.store.save_state(e.state)
        f = [x for fs in self.run_cycles(self.engine(), [(1066.0, obs(ts="2026-01-01T00:01:06Z", ssid="OtherNet",
                                                                          gw_mac=GW_MAC_ALT))])
             for x in fs if x.kind == "GW_MAC_CHANGED"]
        self.assertEqual([(x.severity, x.attribution) for x in f], [("high", None)])

    def test_a_broken_snapshot_gives_the_same_verdicts_as_before(self):
        """(K-7) 스냅샷 키가 없거나 깨졌을 때의 판정은 기준 커밋과 같다 — 내부 값이 아니라 다음 주기의 게이트웨이 MAC 변화 판정으로 본다.
        앵커가 SSID 를 읽은 관측이면 같은 SSID 는 high·다른 SSID 는 이동(low), 앵커가 공백 관측이면 둘 다 이동(low)."""
        values = [("키 없음", None), ("None", "none"), ("숫자", 5), ("목록", ["x"]), ("빈 값", ""), ("상한+1", "a" * 129)]
        for anchor_kind in ("읽음", "공백"):
            for name, value in values:
                for nxt, want in (("같은 SSID", ("high", None) if anchor_kind == "읽음" else ("low", "network_change")),
                                  ("다른 SSID", ("low", "network_change"))):
                    with self.subTest(anchor=anchor_kind, value=name, next=nxt):
                        a = obs(ts="2026-01-01T00:00:00Z", ssid=SSID) if anchor_kind == "읽음" else self.gap(ts="2026-01-01T00:00:00Z")
                        snap = {"ts": a.ts, "data": a.data, "wall": 1000.0}
                        if name != "키 없음":
                            snap["identity_ssid"] = None if value == "none" else value
                        Store(self.dir).save_baseline(snap)
                        cur = obs(ts="2026-01-01T00:00:05Z", ssid=SSID if nxt == "같은 SSID" else "OtherNet", gw_mac=GW_MAC_ALT)
                        f = [x for x in self.engine().judge(cur, 5.0) if x.kind == "GW_MAC_CHANGED"]
                        self.assertEqual([(x.severity, x.attribution) for x in f], [want])

    def test_judging_a_gap_does_not_rewrite_the_observation(self):
        """(AC-5, K-7) 공백 주기의 관측은 판정 뒤에도 그대로다 — 표본에는 SSID 없음과 사유(`helper_unavailable`)가 남는다."""
        import copy
        e = self.engine()
        e.judge(obs(ts="2026-01-01T00:00:00Z", ssid=SSID), 0.0)
        g = self.gap(ts="2026-01-01T00:00:05Z")
        before = copy.deepcopy(g.data)
        e.judge(g, 5.0)
        self.assertEqual(g.data, before)
        self.assertIsNone(g.data["wifi"]["ssid"])
        self.assertTrue(g.data["wifi"]["helper_unavailable"])

    def test_turning_the_consent_off_and_restarting_drops_the_ssid_from_the_snapshot(self):
        """설정은 에이전트가 시작할 때 읽는다 — 동의를 끄고 재시작하면 되살린 값은 쓰이지 않고, 첫 완전한 판정 주기에 지워지며 그 주기에
        스냅샷이 다시 쓰인다(재시작 직후 첫 저장은 60초를 기다리지 않음)."""
        e = self.engine()
        a = obs(ts="2026-01-01T00:00:00Z", ssid=SSID)
        e.judge(a, 0.0)
        e._keep_baseline(a, 1000.0)
        self.assertEqual(Store(self.dir).load_baseline().get("identity_ssid"), SSID)
        self.cfg.revoke("location")
        e2 = self.engine()
        withheld = obs(ts="2026-01-01T00:00:05Z", ssid=None)
        withheld.data["wifi"]["identity_withheld"] = True
        e2.judge(withheld, 5.0)
        self.assertIsNone(e2.identity_ssid)
        e2._keep_baseline(withheld, 1005.0)
        self.assertIsNone(Store(self.dir).load_baseline().get("identity_ssid"))

    def test_a_tampered_snapshot_value_never_reaches_the_output(self):
        """ADV-1 스냅샷의 조작된 문자열(구분자·제어 문자 포함)은 받되 동일성 비교에만 쓰인다 — 판정의 network·증거·state.json 어디에도
        나오지 않는다(_work/redteam.md "출력으로 식별자가 새는가")."""
        import json
        marker = "ZZ-TAMPERED|\n-ZZ"
        store = Store(self.dir)
        g = self.gap(ts="2026-01-01T00:00:00Z")
        store.save_baseline({"ts": g.ts, "data": g.data, "wall": 1000.0, "identity_ssid": marker})
        e = self.engine()
        self.assertEqual(e.identity_ssid, marker)
        out = []
        for i, o in enumerate((self.gap(ts="2026-01-01T00:00:05Z"), obs(ts="2026-01-01T00:00:10Z", ssid=SSID, gw_mac=GW_MAC_ALT),
                               self.gap(ts="2026-01-01T00:00:15Z"))):
            out += [f.as_dict() for f in e.judge(o, 5.0)]
            e.prev = o
        e.store.save_state(e.state)
        blob = json.dumps(out, ensure_ascii=False) + open(os.path.join(self.dir, "state.json"), encoding="utf-8").read()
        self.assertNotIn("ZZ-TAMPERED", blob)


if __name__ == "__main__":
    unittest.main()
