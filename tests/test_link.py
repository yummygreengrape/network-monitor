"""어디서나 netmon 으로 실행되게 하는 링크, 그리고 첫 홉 측정.

`./netmon.sh` 는 저장소 안에서만 통한다. 다른 곳에서 치면 셸이
`no such file or directory` 를 내는데, 이 단계에서는 우리 코드가 아직 돌지
않아 안내를 띄울 수도 없다. 그래서 링크가 필요하다.

이름이 `link` 인 모듈이 둘이다. 실행 링크(`netmon/link.py`)와 연결 품질
측정(`netmon/collect/link.py`)이고, 둘 다 이 파일에서 본다. 측정 쪽은
**실제로 ping 을 보내지 않는다** — `run` 을 대체해 고정값으로 판정한다.
"""
from __future__ import annotations

import os
import tempfile
import threading
import time
import unittest
from unittest import mock

from netmon import link, liveness
from netmon.collect import link as first_hop
from netmon.engine import Engine
from netmon.model import ident
from netmon.util import CmdResult
from tests import helpers


class TestChooseDir(unittest.TestCase):
    def test_prefers_a_writable_dir_already_on_path(self):
        d, why = link.choose_dir(
            candidates=("/a", "/b"), path_value="/x:/b",
            is_writable=lambda p: p in ("/a", "/b"), exists=lambda p: True)
        self.assertEqual(d, "/b")
        self.assertIn("PATH", why)

    def test_falls_back_to_writable_but_not_on_path(self):
        d, why = link.choose_dir(
            candidates=("/a",), path_value="/x",
            is_writable=lambda p: p == "/a", exists=lambda p: True)
        self.assertEqual(d, "/a")
        self.assertIn("PATH 에는 없는", why)

    def test_can_propose_creating_a_dir(self):
        d, why = link.choose_dir(
            candidates=("/parent/child",), path_value="",
            is_writable=lambda p: p == "/parent",
            exists=lambda p: p == "/parent")
        self.assertEqual(d, "/parent/child")
        self.assertIn("만들어야", why)

    def test_reports_failure_instead_of_guessing(self):
        d, _ = link.choose_dir(candidates=("/a",), path_value="",
                               is_writable=lambda p: False, exists=lambda p: False)
        self.assertIsNone(d)

    def test_duplicate_path_entries_are_collapsed(self):
        """PATH 에 같은 곳이 두 번 있으면 링크도 두 번 찾은 것처럼 보인다."""
        self.assertEqual(link.path_dirs("/usr/bin:/usr/bin:/bin"), ["/usr/bin", "/bin"])


class TestInstall(unittest.TestCase):
    def _launcher(self, d):
        p = os.path.join(d, "netmon.sh")
        with open(p, "w") as fh:
            fh.write("#!/bin/bash\n")
        os.chmod(p, 0o755)
        return p

    def test_creates_a_symlink_to_the_launcher(self):
        with tempfile.TemporaryDirectory() as d:
            launcher = self._launcher(d)
            target = os.path.join(d, "bin")
            r = link.install(launcher, target)
            self.assertTrue(r["ok"], r.get("error"))
            self.assertTrue(os.path.islink(r["path"]))
            self.assertEqual(os.path.realpath(r["path"]), os.path.realpath(launcher))

    def test_replaces_an_existing_link(self):
        with tempfile.TemporaryDirectory() as d:
            launcher = self._launcher(d)
            target = os.path.join(d, "bin")
            link.install(launcher, target)
            r = link.install(launcher, target)
            self.assertTrue(r["ok"])

    def test_refuses_to_clobber_a_real_file(self):
        """링크가 아닌 파일이 있으면 건드리지 않는다. 남의 netmon 일 수 있다."""
        with tempfile.TemporaryDirectory() as d:
            launcher = self._launcher(d)
            target = os.path.join(d, "bin")
            os.makedirs(target)
            with open(os.path.join(target, "netmon"), "w") as fh:
                fh.write("다른 프로그램")
            r = link.install(launcher, target)
            self.assertFalse(r["ok"])
            self.assertIn("링크가 아닌 파일", r["error"])

    def test_missing_launcher_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            r = link.install(os.path.join(d, "없는파일.sh"), d)
            self.assertFalse(r["ok"])

    def test_path_hint_matches_the_shell(self):
        self.assertIn(".zshrc", link.path_hint("/opt/x", shell="zsh"))
        self.assertIn(".bash_profile", link.path_hint("/opt/x", shell="bash"))
        self.assertIn("/opt/x", link.path_hint("/opt/x", shell="zsh"))


# --- 첫 홉 측정 (netmon/collect/link.py) ---

GW = "192.0.2.1"
RESOLVER = "198.51.100.53"
PUBLIC = "203.0.113.9"

REPLY = ("PING 192.0.2.1 (192.0.2.1): 56 data bytes\n"
         "64 bytes from 192.0.2.1: icmp_seq=0 ttl=64 time=12.30 ms\n"
         "\n--- 192.0.2.1 ping statistics ---\n"
         "1 packets transmitted, 1 packets received, 0.0% packet loss\n")
LOST = ("PING 192.0.2.1 (192.0.2.1): 56 data bytes\n"
        "\n--- 192.0.2.1 ping statistics ---\n"
        "1 packets transmitted, 0 packets received, 100.0% packet loss\n")


def reply_with(ms):
    return REPLY.replace("time=12.30 ms", "time=%.2f ms" % ms)


class FakeRun:
    """`run` 을 대신한다. 실제 네트워크로 아무것도 보내지 않는다."""

    def __init__(self, outs=None, delay=0.0, barrier=None, rc=0, timed_out=False):
        # outs: 호출 순서대로 돌려줄 출력. 모자라면 마지막 것을 되쓴다.
        self.outs = list(outs) if outs else [REPLY]
        self.delay = delay
        self.barrier = barrier
        self.rc = rc
        self.timed_out = timed_out
        self.calls = []
        self._lock = threading.Lock()

    def __call__(self, argv, timeout=None, stdin=""):
        with self._lock:
            i = len(self.calls)
            self.calls.append({"argv": list(argv), "timeout": timeout})
        if self.barrier is not None:
            self.barrier.wait(timeout=5)
        if self.delay:
            time.sleep(self.delay)
        out = self.outs[i] if i < len(self.outs) else self.outs[-1]
        return CmdResult(list(argv), self.rc, out, "", timed_out=self.timed_out)

    def targets(self):
        return [c["argv"][-1] for c in self.calls]


def collect_with(fake, **ctx):
    base = {"gateway": GW}
    base.update(ctx)
    with mock.patch.object(first_hop, "run", fake):
        return first_hop.collect(base)


class TestFirstHopNormalCycle(unittest.TestCase):
    """평소 주기는 지금과 똑같이 1발이다 (QA-1, AC-1, AC-12)."""

    def test_sends_exactly_one_packet_with_the_same_command(self):
        fake = FakeRun()
        out = collect_with(fake)
        self.assertEqual(len(fake.calls), 1)
        self.assertEqual(fake.calls[0]["argv"],
                         ["ping", "-n", "-c", "1", "-W", "800", GW])
        self.assertEqual(out["first_hop_probes"], 1)
        self.assertTrue(out["gateway_reachable"])
        self.assertEqual(out["gateway_rtt_ms"], 12.3)

    def test_single_shot_result_shape_is_unchanged(self):
        out = collect_with(FakeRun())
        self.assertEqual(set(out["results"]["gateway"]),
                         {"rtt_ms", "rtt_max_ms", "loss_pct", "replies", "reachable"})

    def test_ping_count_setting_is_still_honoured(self):
        fake = FakeRun()
        collect_with(fake, ping_count=2)
        self.assertEqual(len(fake.calls), 1)
        self.assertEqual(fake.calls[0]["argv"][3], "2")

    def test_default_count_is_one(self):
        self.assertEqual(first_hop.DEFAULT_COUNT, 1)


class TestAnomalyHint(unittest.TestCase):
    """다발을 켜는 조건 (QA-3, AC-2)."""

    OK_LINK = {"gateway_reachable": True}
    CONNECTED = {"warp": {"state": "connected"}}
    OFF = {"warp": {"state": "disconnected"}}

    def test_quiet_cycle_is_not_an_anomaly(self):
        self.assertFalse(first_hop.first_hop_anomaly(
            self.OK_LINK, self.CONNECTED, self.CONNECTED))

    def test_previous_first_hop_silent(self):
        self.assertTrue(first_hop.first_hop_anomaly(
            {"gateway_reachable": False}, self.CONNECTED, self.CONNECTED))

    def test_a_provider_left_switched_off_never_turns_it_on(self):
        """설치만 해 두고 꺼 둔 공급자 때문에 매 주기 3발이 나가면 안 된다."""
        for _ in range(5):
            self.assertFalse(first_hop.first_hop_anomaly(
                self.OK_LINK, self.OFF, self.OFF))

    def test_a_disconnection_that_just_happened(self):
        self.assertTrue(first_hop.first_hop_anomaly(
            self.OK_LINK, {"warp": {"state": "connecting"}}, self.CONNECTED))

    def test_previous_vpn_state_changed(self):
        """직전 주기의 상태가 connected 여도, 그 앞과 다르면 켠다."""
        self.assertTrue(first_hop.first_hop_anomaly(
            self.OK_LINK, self.CONNECTED, {"warp": {"state": "connecting"}}))

    def test_a_provider_appearing_or_vanishing_counts_as_a_change(self):
        self.assertTrue(first_hop.first_hop_anomaly(self.OK_LINK, self.CONNECTED, {}))
        self.assertTrue(first_hop.first_hop_anomaly(self.OK_LINK, {}, self.CONNECTED))

    def test_no_vpn_block_is_not_an_anomaly(self):
        """VPN 감시를 끈 사람에게 없던 패킷이 생기지 않는다."""
        self.assertFalse(first_hop.first_hop_anomaly(self.OK_LINK, None, None))
        self.assertFalse(first_hop.first_hop_anomaly(None, None, None))
        self.assertFalse(first_hop.first_hop_anomaly(self.OK_LINK, None, {}))

    def test_unmeasured_first_hop_is_not_called_silent(self):
        """측정하지 않은 것(None)은 무응답이 아니다."""
        self.assertFalse(first_hop.first_hop_anomaly({"gateway_reachable": None},
                                                     None, None))


class TestAnomalyHintFollowsTheLivenessMethod(unittest.TestCase):
    """무응답 판정을 이 망의 판정 방법으로 본다 (QA-3, AC-2, DEV-6).

    ICMP 를 막아 둔 게이트웨이에서는 `gateway_reachable` 이 정상 상태에도
    매 주기 False 다. 그것을 이상 징후로 세면 아무 일도 없는데 주기마다
    다발이 나간다 — liveness 가 ARP 로 판정을 바꾸는 바로 그 망이다.
    """

    ARP_OK = {"gateway_mac": ident("mac", helpers.GW_MAC), "neighbors": 4}
    ARP_GONE = {"gateway_mac": None, "neighbors": 4}
    ICMP_SILENT = {"gateway_reachable": False}
    ICMP_OK = {"gateway_reachable": True}
    CONNECTED = {"warp": {"state": "connected"}}

    def hint(self, link_block, arp_block, method):
        return first_hop.first_hop_anomaly(link_block, self.CONNECTED, self.CONNECTED,
                                           prev_arp=arp_block, method=method)

    def test_icmp_silent_network_never_turns_it_on_while_things_are_fine(self):
        for _ in range(5):
            self.assertFalse(self.hint(self.ICMP_SILENT, self.ARP_OK, liveness.ARP))

    def test_icmp_silent_network_watches_the_arp_signal_instead(self):
        """그 망에서는 `arp.gateway_mac` 이 빈 것을 이상 징후로 센다.

        liveness 가 그 망에서 도달성을 판정하는 신호가 이것이라서다. **이 신호가
        실제 끊김을 드러낸다는 근거는 없다** — 보관 샘플에는 첫 홉이 살아 있는데도
        이 값이 빈 주기가 있고, 끊긴 뒤 언제 비는지는 모른다
        (netmon/collect/link.py 의 주석). 여기서 고정하는 것은 입력→출력뿐이다.
        """
        self.assertTrue(self.hint(self.ICMP_SILENT, self.ARP_GONE, liveness.ARP))

    def test_an_arp_collector_failure_is_not_an_outage(self):
        """블록이 통째로 비면 수집 실패다. 모르는 것을 근거로 쏘지 않는다.

        `liveness.evaluate` 는 같은 입력을 ARP 판정 망에서 "죽음" 으로 읽어
        `gw_fail_streak` 를 올린다. 다발 판단은 보수적인 쪽으로 갈라진다.
        """
        self.assertFalse(self.hint(self.ICMP_SILENT, {}, liveness.ARP))
        self.assertFalse(self.hint(self.ICMP_SILENT, None, liveness.ARP))

    def test_icmp_network_keeps_the_old_behaviour(self):
        self.assertTrue(self.hint(self.ICMP_SILENT, self.ARP_OK, liveness.ICMP))
        self.assertFalse(self.hint(self.ICMP_OK, self.ARP_GONE, liveness.ICMP))
        self.assertFalse(self.hint({"gateway_reachable": None}, self.ARP_OK,
                                   liveness.ICMP))

    def test_while_calibrating_a_live_signal_wins(self):
        """보정 중에는 liveness.evaluate 와 같은 우선순위다."""
        self.assertFalse(self.hint(self.ICMP_SILENT, self.ARP_OK, liveness.UNKNOWN))
        self.assertFalse(self.hint(self.ICMP_OK, self.ARP_GONE, liveness.UNKNOWN))
        self.assertFalse(self.hint({"gateway_reachable": None}, self.ARP_GONE,
                                   liveness.UNKNOWN))

    def test_while_calibrating_both_signals_failing_turns_it_on(self):
        """여기서는 `liveness.evaluate` 와 갈라진다 — 일부러 그렇다.

        같은 입력에서 liveness 는 `link_active` 까지 본다 — 그 값이 False 면
        `(LINK, False)` 로 판정하고, 그 밖일 때만 보류한다(None). 다발 판단은
        어느 쪽이든 보류하지 않고 재 본다. 측정을 늘리는 쪽이라 판정을
        만들지 않는다.
        """
        self.assertTrue(self.hint(self.ICMP_SILENT, self.ARP_GONE, liveness.UNKNOWN))

    def test_the_vpn_branch_is_untouched(self):
        """판정 방법과 무관하게 VPN 상태 변화는 그대로 켠다."""
        for method, quiet_link in ((liveness.ARP, self.ICMP_SILENT),
                                   (liveness.ICMP, self.ICMP_OK),
                                   (liveness.UNKNOWN, self.ICMP_SILENT)):
            self.assertTrue(first_hop.first_hop_anomaly(
                quiet_link, self.CONNECTED, {"warp": {"state": "connecting"}},
                prev_arp=self.ARP_OK, method=method))
            self.assertFalse(first_hop.first_hop_anomaly(
                quiet_link, self.CONNECTED, self.CONNECTED,
                prev_arp=self.ARP_OK, method=method))


class TestBurstCycle(unittest.TestCase):
    """이상 징후 주기의 다발 측정 (QA-2, AC-1, AC-3)."""

    def burst(self, fake, **ctx):
        return collect_with(fake, first_hop_burst=True, interval=5, **ctx)

    def test_three_single_packet_pings(self):
        fake = FakeRun()
        out = self.burst(fake)
        self.assertEqual(len(fake.calls), 3)
        for c in fake.calls:
            self.assertEqual(c["argv"], ["ping", "-n", "-c", "1", "-W", "800", GW])
        self.assertEqual(out["first_hop_probes"], 3)

    def test_records_sent_received_loss_and_rtt_range(self):
        fake = FakeRun(outs=[reply_with(10.0), LOST, reply_with(30.0)])
        g = self.burst(fake)["results"]["gateway"]
        self.assertEqual(g["sent"], 3)
        self.assertEqual(g["received"], 2)
        self.assertEqual(g["loss_pct"], 33.3)
        self.assertEqual(g["rtt_min_ms"], 10.0)
        self.assertEqual(g["rtt_max_ms"], 30.0)
        self.assertTrue(g["reachable"])

    def test_evidence_says_the_probes_were_simultaneous(self):
        """읽는 쪽이 시간에 걸친 지터로 오해하지 않게 관측에 적는다."""
        g = self.burst(FakeRun())["results"]["gateway"]
        self.assertEqual(g["mode"], "burst")
        self.assertTrue(g["concurrent"])
        self.assertIn("동시", g["note"])

    def test_burst_is_not_serialised_next_to_other_targets(self):
        """게이트웨이 3발 + 리졸버 + 공개 IP 가 모두 같은 순간에 나간다."""
        barrier = threading.Barrier(5)
        fake = FakeRun(barrier=barrier)
        seen = []
        real = first_hop.concurrent.futures.ThreadPoolExecutor

        def recording(max_workers=None, **kw):
            seen.append(max_workers)
            return real(max_workers=max_workers, **kw)

        with mock.patch.object(first_hop.concurrent.futures, "ThreadPoolExecutor",
                               recording):
            out = self.burst(fake, resolver_external=RESOLVER,
                             allow_external=True, external_target=PUBLIC)
        self.assertEqual(len(fake.calls), 5)          # 막히지 않고 다섯이 다 돌았다
        self.assertEqual(seen, [5])                   # worker 수 >= 작업 수
        self.assertNotIn("errors", out["results"]["gateway"])
        self.assertEqual(out["results"]["gateway"]["received"], 3)
        self.assertEqual(sorted(fake.targets()), sorted([GW, GW, GW, PUBLIC, RESOLVER]))

    def test_other_targets_keep_one_probe_each(self):
        fake = FakeRun()
        out = self.burst(fake, resolver_external=RESOLVER)
        self.assertEqual(fake.targets().count(RESOLVER), 1)
        self.assertNotIn("sent", out["results"]["resolver"])


class TestBurstFitsTheCycle(unittest.TestCase):
    """다발이 주기를 넘기지 않는다 (QA-4, AC-3)."""

    def test_individual_wait_is_unchanged(self):
        self.assertEqual(first_hop.DEFAULT_WAIT_MS, 800)

    def test_timeouts_are_larger_than_the_measured_duration(self):
        """제한 시간이 먼저 끊으면 손실률이 네트워크가 아니라 우리 탓이 된다."""
        one = first_hop.ping_seconds()
        self.assertAlmostEqual(one, 1.8, places=2)   # 실측 1.84초와 같은 자리
        self.assertGreater(first_hop.PING_TIMEOUT_SECONDS, one)
        self.assertGreater(first_hop.RESULT_WAIT_SECONDS,
                           first_hop.PING_TIMEOUT_SECONDS)

    def test_subprocess_timeout_is_passed_down(self):
        fake = FakeRun()
        collect_with(fake, first_hop_burst=True, interval=5)
        for c in fake.calls:
            self.assertEqual(c["timeout"], first_hop.PING_TIMEOUT_SECONDS)

    def test_three_probes_take_about_as_long_as_one(self):
        """가짜 run 으로 소요를 고정해서 잰다.

        판정은 벽시계가 아니라 Barrier 로 한다 — 세 발이 모두 도착해야 풀리므로,
        직렬로 돌면 barrier 가 깨져 응답 수가 모자란다. 부하가 큰 기계에서
        시간 비교만으로 판정하면 흔들린다.
        """
        delay = 0.1
        fake = FakeRun(delay=delay, barrier=threading.Barrier(3))
        t0 = time.monotonic()
        g = collect_with(fake, first_hop_burst=True,
                         interval=5)["results"]["gateway"]
        spent = time.monotonic() - t0
        self.assertEqual(g["received"], 3)        # 셋이 같은 순간에 돌았다
        self.assertNotIn("errors", g)
        self.assertLess(spent, delay * 3)         # 직렬이면 최소 세 배다

    def test_no_burst_while_the_cycle_is_short(self):
        """조사 중 2~3초 주기에서는 다발을 하지 않는다."""
        fake = FakeRun()
        out = collect_with(fake, first_hop_burst=True, interval=2.5)
        self.assertEqual(len(fake.calls), 1)
        self.assertEqual(out["first_hop_probes"], 1)
        self.assertEqual(first_hop.burst_probes({"first_hop_burst": True,
                                                 "interval": 3.0}), 3)

    def test_unknown_interval_still_bursts(self):
        self.assertEqual(first_hop.burst_probes({"first_hop_burst": True}), 3)
        self.assertEqual(first_hop.burst_probes({"first_hop_burst": True,
                                                 "interval": "?"}), 3)


class TestBurstPartialFailure(unittest.TestCase):
    """다발이 부분적으로 실패해도 관측으로 끝난다 (ADV-4, AC-1, AC-3)."""

    def burst(self, fake, **ctx):
        return collect_with(fake, first_hop_burst=True, interval=5, **ctx)

    def test_only_one_of_three_answers(self):
        g = self.burst(FakeRun(outs=[LOST, reply_with(9.0), LOST]))["results"]["gateway"]
        self.assertEqual((g["sent"], g["received"]), (3, 1))
        self.assertEqual(g["loss_pct"], 66.7)
        self.assertFalse(g["reachable"])          # 첫 발이 답하지 않았다
        self.assertTrue(g["any_reachable"])       # 그래도 하나는 왔다 (증거)

    def test_nothing_answers(self):
        g = self.burst(FakeRun(outs=[LOST]))["results"]["gateway"]
        self.assertEqual((g["sent"], g["received"]), (3, 0))
        self.assertEqual(g["loss_pct"], 100.0)
        self.assertFalse(g["reachable"])
        self.assertIsNone(g["rtt_ms"])
        self.assertIsNone(g["rtt_min_ms"])

    def test_command_itself_fails(self):
        g = self.burst(FakeRun(outs=[""], rc=127))["results"]["gateway"]
        self.assertEqual((g["sent"], g["received"]), (3, 0))
        self.assertEqual(g["loss_pct"], 100.0)

    def test_command_times_out(self):
        g = self.burst(FakeRun(outs=[""], timed_out=True))["results"]["gateway"]
        self.assertEqual((g["sent"], g["received"]), (3, 0))
        self.assertEqual(g["loss_pct"], 100.0)

    def test_a_probe_raising_is_an_observation_not_an_exception(self):
        def boom(target, count=1, **kw):
            if boom.n:
                boom.n -= 1
                raise RuntimeError("측정 실패")
            return {"rtt_ms": 5.0, "rtt_max_ms": 5.0, "loss_pct": 0.0,
                    "replies": 1, "reachable": True}
        boom.n = 2
        with mock.patch.object(first_hop, "ping", boom):
            out = first_hop.collect({"gateway": GW, "first_hop_burst": True,
                                     "interval": 5})
        g = out["results"]["gateway"]
        self.assertEqual((g["sent"], g["received"]), (3, 1))
        self.assertEqual(g["loss_pct"], 66.7)
        self.assertEqual(g["errors"], ["측정 실패"])

    def test_loss_stays_inside_the_observed_range(self):
        for outs in ([LOST], [REPLY], [REPLY, LOST, LOST]):
            g = self.burst(FakeRun(outs=outs))["results"]["gateway"]
            self.assertGreaterEqual(g["loss_pct"], 0.0)
            self.assertLessEqual(g["loss_pct"], 100.0)
            self.assertEqual(g["sent"], 3)

    def test_no_gateway_means_no_measurement(self):
        fake = FakeRun()
        with mock.patch.object(first_hop, "run", fake):
            out = first_hop.collect({"first_hop_burst": True, "interval": 5})
        self.assertEqual(fake.calls, [])
        self.assertEqual(out["targets"], {})
        self.assertNotIn("first_hop_probes", out)


class TestEngineRemembersTheLastTwoCycles(unittest.TestCase):
    """엔진이 직전 주기(그리고 그 앞)를 제대로 들고 있는가 (QA-3, AC-2).

    수집은 돌리지 않는다 — 합성 관측을 그대로 기억시키고 판단만 본다.
    """

    def _engine(self, *observations, state=None):
        eng = Engine.__new__(Engine)
        # 보정 상태는 판정 방법을 정한다. 주지 않으면 보정 중(unknown)이다.
        eng.state = dict(state or {})
        for o in observations:
            eng._remember_for_burst(o)
        return eng

    def test_first_cycle_is_quiet(self):
        self.assertFalse(self._engine()._burst_hint())

    def test_quiet_cycles_stay_quiet(self):
        eng = self._engine(helpers.obs(vpn=helpers.vpn_state("connected")),
                           helpers.obs(vpn=helpers.vpn_state("connected")))
        self.assertFalse(eng._burst_hint())

    def test_silent_first_hop_last_cycle_turns_it_on(self):
        """ICMP 로 판정하는 망에서는 종전 그대로다."""
        eng = self._engine(helpers.obs(vpn=helpers.vpn_state("connected")),
                           helpers.obs(icmp_ok=False,
                                       vpn=helpers.vpn_state("connected")),
                           state={"icmp_gw": True})
        self.assertTrue(eng._burst_hint())

    def test_an_icmp_silent_network_stays_quiet(self):
        """게이트웨이가 ICMP 를 막아 둔 망(보정 결과 ARP 판정).

        그 망에서는 `gateway_reachable` 이 정상 상태에도 매 주기 False 라,
        그것만 보고 켜면 아무 일도 없는데 5초마다 3발이 나간다 (AC-2).
        """
        eng = self._engine(state={"icmp_gw": False})
        for _ in range(5):
            eng._remember_for_burst(helpers.obs(icmp_ok=False,
                                                vpn=helpers.vpn_state("connected")))
            self.assertFalse(eng._burst_hint())

    def test_an_icmp_silent_network_turns_it_on_when_the_arp_signal_goes(self):
        """같은 망에서 `arp.gateway_mac` 이 비면 켠다.

        그 망의 도달성 판정 신호가 그것이기 때문이다. 이 신호가 실제 끊김을
        드러낸다는 근거는 없다(netmon/collect/link.py 의 주석).
        """
        eng = self._engine(helpers.obs(icmp_ok=False,
                                       vpn=helpers.vpn_state("connected")),
                           helpers.obs(icmp_ok=False, gw_mac=None,
                                       vpn=helpers.vpn_state("connected")),
                           state={"icmp_gw": False})
        self.assertTrue(eng._burst_hint())

    def test_a_network_being_calibrated_stays_quiet_while_arp_is_fine(self):
        """보정 중(unknown)에는 liveness 와 같은 우선순위로 본다."""
        eng = self._engine(helpers.obs(vpn=helpers.vpn_state("connected")),
                           helpers.obs(icmp_ok=False,
                                       vpn=helpers.vpn_state("connected")))
        self.assertFalse(eng._burst_hint())

    def test_a_state_change_one_cycle_ago_turns_it_on(self):
        """직전 주기에 다시 connected 가 됐어도, 바뀐 주기 다음은 재 본다."""
        eng = self._engine(helpers.obs(vpn=helpers.vpn_state("connecting")),
                           helpers.obs(vpn=helpers.vpn_state("connected")))
        self.assertTrue(eng._burst_hint())

    def test_it_goes_quiet_again_two_cycles_later(self):
        eng = self._engine(helpers.obs(vpn=helpers.vpn_state("connecting")),
                           helpers.obs(vpn=helpers.vpn_state("connected")),
                           helpers.obs(vpn=helpers.vpn_state("connected")))
        self.assertFalse(eng._burst_hint())

    def test_a_cycle_without_a_link_still_counts(self):
        """판정을 건너뛰는 주기야말로 다음 주기를 다발로 재야 할 이유다."""
        eng = self._engine(helpers.obs(vpn=helpers.vpn_state("connected")),
                           helpers.obs(gateway=None, icmp_ok=None,
                                       vpn=helpers.vpn_state("disconnected")))
        self.assertTrue(eng._burst_hint())


class TestBurstDoesNotChangeExistingJudgements(unittest.TestCase):
    """다발이 기존 판정을 바꾸지 않는다 (AC-1b).

    `gateway_reachable`·`gateway_rtt_ms` 는 첫 홉 연속 실패 셈과 지연
    기준선으로 흘러간다 (netmon/liveness.py, netmon/baseline.py).
    여기서 값이 바뀌면 `FIRST_HOP_BRIEF_GAP` 이 전과 다르게 뜬다.
    """

    def burst(self, outs):
        return collect_with(FakeRun(outs=outs), first_hop_burst=True, interval=5)

    def test_reachability_follows_the_first_probe(self):
        first_lost = self.burst([LOST, REPLY, REPLY])
        self.assertFalse(first_lost["gateway_reachable"])
        self.assertIsNone(first_lost["gateway_rtt_ms"])
        first_ok = self.burst([reply_with(7.0), LOST, LOST])
        self.assertTrue(first_ok["gateway_reachable"])
        self.assertEqual(first_ok["gateway_rtt_ms"], 7.0)

    def test_rtt_baseline_gets_the_first_probe_not_the_average(self):
        """느린 두 발이 기준선을 끌어올리면 RTT_SPIKE 판정이 달라진다."""
        out = self.burst([reply_with(10.0), reply_with(300.0), reply_with(300.0)])
        self.assertEqual(out["gateway_rtt_ms"], 10.0)

    def test_fail_streak_counts_the_same_as_a_single_shot_cycle(self):
        """1/3 응답 주기가 연속 실패 셈을 초기화하지 않는다."""
        from netmon import baseline

        def streak(observation):
            state = {"icmp_gw": True, "gw_fail_streak": 4}
            return baseline.update_counters(state, observation, [], 5.0, 5.0)

        partial = self.burst([LOST, reply_with(9.0), LOST])
        burst_obs = helpers.obs(icmp_ok=None)
        burst_obs.data["link"] = partial
        single = helpers.obs(icmp_ok=False)
        self.assertEqual(streak(burst_obs)["gw_fail_streak"],
                         streak(single)["gw_fail_streak"])
        self.assertEqual(streak(burst_obs)["gw_fail_streak"], 5)

    def test_a_burst_whose_first_probe_answers_clears_the_streak_as_before(self):
        from netmon import baseline

        out = self.burst([reply_with(9.0), LOST, LOST])
        o = helpers.obs(icmp_ok=None)
        o.data["link"] = out
        new = baseline.update_counters({"icmp_gw": True, "gw_fail_streak": 4},
                                       o, [], 5.0, 5.0)
        self.assertEqual(new["gw_fail_streak"], 0)
        self.assertEqual(new["gw_fail_streak_prev"], 4)


class TestPingCountInteraction(unittest.TestCase):
    """`ping_count` 를 올려 둔 사람 (QA-13, AC-12)."""

    def test_burst_never_sends_fewer_than_the_configured_count(self):
        fake = FakeRun()
        out = collect_with(fake, first_hop_burst=True, interval=5, ping_count=5)
        self.assertEqual(len(fake.calls), 5)
        for c in fake.calls:
            self.assertEqual(c["argv"][3], "1")   # 다발은 1발씩 쪼개서 동시에
        self.assertEqual(out["first_hop_probes"], 5)
        self.assertEqual(out["results"]["gateway"]["sent"], 5)

    def test_the_usual_three_when_the_count_is_the_default(self):
        fake = FakeRun()
        collect_with(fake, first_hop_burst=True, interval=5, ping_count=1)
        self.assertEqual(len(fake.calls), 3)


if __name__ == "__main__":
    unittest.main()
