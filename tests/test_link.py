"""어디서나 netmon 으로 실행되게 하는 링크, 그리고 첫 홉 측정.

`./netmon.sh` 는 저장소 안에서만 통한다. 다른 곳에서 치면 셸이
`no such file or directory` 를 내는데, 이 단계에서는 우리 코드가 아직 돌지
않아 안내를 띄울 수도 없다. 그래서 링크가 필요하다.

이름이 `link` 인 모듈이 둘이다. 실행 링크(`netmon/link.py`)와 연결 품질
측정(`netmon/collect/link.py`)이고, 둘 다 이 파일에서 본다. 측정 쪽은
**실제로 ping 을 보내지 않는다** — `run` 을 대체해 고정값으로 판정한다.
"""
from __future__ import annotations

import contextlib
import os
import shutil
import tempfile
import threading
import time
import unittest
from unittest import mock

from netmon import config as configmod
from netmon import engine as enginemod
from netmon import link, liveness
from netmon import vpn as vpnmod
from netmon.collect import link as first_hop
from netmon.engine import Engine
from netmon import util
from netmon.model import PROBE_NOT_RUN, PROBE_TIMED_OUT, ident
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


# --- 터널 엔드포인트 (AC-4, AC-4b, AC-4c) ---

ENDPOINT = helpers.ENDPOINT


class TestTunnelEndpointTarget(unittest.TestCase):
    """동의·기능이 켜졌을 때만, 공인 유니캐스트에만 (QA-5, ADV-5, ADV-6)."""

    def test_without_the_gate_nothing_goes_out_and_nothing_is_recorded(self):
        """동의·기능이 없으면 관측 항목도 만들지 않는다 (AC-4)."""
        fake = FakeRun()
        out = collect_with(fake, tunnel_endpoint=ENDPOINT)
        self.assertEqual(fake.targets(), [GW])
        self.assertNotIn("tunnel_endpoint", out["targets"])
        self.assertNotIn("tunnel_endpoint", out["results"])

    def test_the_gate_alone_sends_nothing(self):
        """주소를 모르는 주기 — 끊김 첫 주기가 이쪽이다 (AC-4c)."""
        fake = FakeRun()
        out = collect_with(fake, allow_tunnel_probe=True)
        self.assertEqual(fake.targets(), [GW])
        self.assertNotIn("tunnel_endpoint", out["results"])

    def test_with_both_it_is_measured_and_the_address_is_wrapped(self):
        fake = FakeRun()
        out = collect_with(fake, allow_tunnel_probe=True, tunnel_endpoint=ENDPOINT)
        self.assertEqual(sorted(fake.targets()), sorted([GW, ENDPOINT]))
        self.assertEqual(out["targets"]["tunnel_endpoint"], ident("ipv4", ENDPOINT))
        self.assertTrue(out["results"]["tunnel_endpoint"]["reachable"])

    def test_blocked_addresses_are_never_probed(self):
        """대상 주소를 외부 문자열이 정한다 (ADV-6).

        부르는 쪽이 이미 걸렀어야 하지만, 여기서도 다시 본다.
        """
        for addr in ("127.0.0.1", "::1", "169.254.0.0", "224.0.0.0",
                     "255.255.255.255", "10.0.0.0", "192.168.0.0", "172.16.0.0",
                     "100.64.0.0", "0.0.0.0", "fe80::1", "not-an-address"):
            fake = FakeRun()
            out = collect_with(fake, allow_tunnel_probe=True, tunnel_endpoint=addr)
            self.assertEqual(fake.targets(), [GW], addr)
            self.assertNotIn("tunnel_endpoint", out["results"], addr)

    def test_it_does_not_change_the_first_hop_verdict(self):
        """판정이 읽는 값은 게이트웨이 것 그대로다 (AC-1b, AC-12)."""
        fake = FakeRun(outs=[REPLY, LOST])
        out = collect_with(fake, allow_tunnel_probe=True, tunnel_endpoint=ENDPOINT)
        self.assertTrue(out["gateway_reachable"])
        self.assertEqual(out["gateway_rtt_ms"], 12.3)
        self.assertEqual(out["first_hop_probes"], 1)

    def test_a_failure_records_only_the_error_kind(self):
        """엔드포인트의 실패 문구에는 주소가 섞일 수 있다 (DEV-8 검수 지적).

        감싸지 않은 문자열은 내보낼 때도 가려지지 않으므로, 이 대상만
        예외 종류 이름까지 남긴다. 다른 대상의 문구는 종전 그대로다.
        """
        def exploding(argv, timeout=None, stdin=""):
            raise RuntimeError("ping %s failed" % argv[-1])

        with mock.patch.object(first_hop, "run", exploding):
            out = first_hop.collect({"gateway": GW, "allow_tunnel_probe": True,
                                     "tunnel_endpoint": ENDPOINT})
        endpoint = out["results"]["tunnel_endpoint"]
        self.assertEqual(endpoint["error"], "RuntimeError")
        self.assertNotIn(ENDPOINT, endpoint["error"])
        self.assertFalse(endpoint["reachable"])
        # 게이트웨이 쪽 문구는 종전처럼 메시지를 남긴다.
        self.assertIn("failed", out["results"]["gateway"]["error"])


class TestTunnelEndpointRidesWithTheBurst(unittest.TestCase):
    """같은 묶음에서 동시에 나간다 (QA-22, AC-4c).

    직렬로 뒤에 붙이면 무응답 대상 기준 약 1.84초가 더 들어 조사 중 2~3초
    주기를 넘긴다.
    """

    def test_four_jobs_one_moment(self):
        barrier = threading.Barrier(4)     # 네 발이 다 도착해야 풀린다
        fake = FakeRun(barrier=barrier)
        seen = []
        real = first_hop.concurrent.futures.ThreadPoolExecutor

        def recording(max_workers=None, **kw):
            seen.append(max_workers)
            return real(max_workers=max_workers, **kw)

        with mock.patch.object(first_hop.concurrent.futures, "ThreadPoolExecutor",
                               recording):
            out = collect_with(fake, first_hop_burst=True, interval=5,
                               allow_tunnel_probe=True, tunnel_endpoint=ENDPOINT)
        self.assertEqual(len(fake.calls), 4)
        self.assertEqual(seen, [4])        # worker 수 = 작업 수. 직렬화되지 않는다
        self.assertEqual(sorted(fake.targets()), sorted([GW, GW, GW, ENDPOINT]))
        self.assertEqual(out["results"]["gateway"]["sent"], 3)
        self.assertNotIn("sent", out["results"]["tunnel_endpoint"])


class TestTheEndpointHonoursPingCount(unittest.TestCase):
    """엔드포인트도 `ping_count` 만큼 보낸다 (AC-4 수정분).

    README 가 "ICMP 한 발" 이라고 적고 있었는데, 실제로는 설정값만큼 나간다
    (`collect/link.collect` 의 `per`). 설정을 올려 둔 사람에게는 틀린
    문장이었다.
    """

    def _endpoint_call(self, fake):
        return [c for c in fake.calls if c["argv"][-1] == ENDPOINT][0]

    def test_the_default_is_one_packet(self):
        fake = FakeRun()
        collect_with(fake, allow_tunnel_probe=True, tunnel_endpoint=ENDPOINT)
        self.assertEqual(self._endpoint_call(fake)["argv"][3], "1")

    def test_a_raised_setting_raises_the_endpoint_too(self):
        fake = FakeRun()
        collect_with(fake, ping_count=3, allow_tunnel_probe=True,
                     tunnel_endpoint=ENDPOINT)
        self.assertEqual(self._endpoint_call(fake)["argv"][3], "3")


class TestTheCollectorMarksACappedCycle(unittest.TestCase):
    """상한에 닿아 보내지 않은 주기를 관측에서 알아볼 수 있는가 (AC-4 수정분).

    결과를 만들지 않는 이유는 여럿이다(동의 없음, 주소 모름, 상한). 셋이
    같은 모양이면 기록을 읽는 쪽이 왜 안 보냈는지 알 수 없다.
    """

    def test_a_capped_cycle_is_marked_and_sends_nothing(self):
        fake = FakeRun()
        out = collect_with(fake, allow_tunnel_probe=True, tunnel_endpoint=None,
                           tunnel_probe_capped=True)
        self.assertTrue(out[first_hop.TUNNEL_CAPPED])
        self.assertNotIn(ENDPOINT, fake.targets())
        self.assertNotIn("tunnel_endpoint", out["results"])
        self.assertNotIn("tunnel_endpoint", out["targets"])

    def test_the_mark_survives_a_cycle_with_no_targets_at_all(self):
        """게이트웨이를 모르는 주기에도 남는다 — 그 주기가 바로 끊김 주기다."""
        fake = FakeRun()
        with mock.patch.object(first_hop, "run", fake):
            out = first_hop.collect({"tunnel_probe_capped": True})
        self.assertTrue(out[first_hop.TUNNEL_CAPPED])
        self.assertEqual(out["targets"], {})
        self.assertEqual(fake.calls, [])

    def test_a_normal_cycle_carries_no_mark(self):
        out = collect_with(FakeRun())
        self.assertNotIn(first_hop.TUNNEL_CAPPED, out)
        out = collect_with(FakeRun(), allow_tunnel_probe=True,
                           tunnel_endpoint=ENDPOINT)
        self.assertNotIn(first_hop.TUNNEL_CAPPED, out)


class TestEngineDecidesWhetherToProbeTheEndpoint(unittest.TestCase):
    """직전 주기의 VPN 상태와 동의로 정한다 (QA-5, QA-19, QA-22, ADV-5).

    수집은 돌리지 않는다 — 합성 관측을 기억시키고 판단만 본다.
    """

    def _engine(self, *observations, consent=True, feature=True):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        cfg = configmod.load(os.path.join(d, "config.json"))
        if consent:
            cfg.grant("external_probes", note="테스트")
        cfg.set_feature("vpn.tunnel_probe", feature)
        eng = Engine.__new__(Engine)
        eng.cfg = cfg
        eng.state = {}
        for o in observations:
            eng._remember_for_burst(o)
        return eng

    def _down(self, reason=helpers.ENDPOINT_REASON, state="disconnected"):
        return helpers.obs(vpn=helpers.vpn_state(state, reason=reason))

    def test_a_cycle_after_a_disconnection_gets_the_address(self):
        self.assertEqual(self._engine(self._down())._claim_tunnel_probe()[0], ENDPOINT)

    def test_the_first_cycle_of_an_outage_has_no_address_yet(self):
        """직전 주기가 connected 면 주소가 없다. 한 주기 늦게 시작된다 (AC-4c)."""
        eng = self._engine(helpers.obs(vpn=helpers.vpn_state("connected")))
        self.assertIsNone(eng._claim_tunnel_probe()[0])

    def test_a_normal_cycle_sends_nothing(self):
        """평소 주기에는 보내지 않는다 (QA-19)."""
        eng = self._engine(helpers.obs(vpn=helpers.vpn_state(
            "connected", reason=helpers.ENDPOINT_REASON)))
        self.assertIsNone(eng._claim_tunnel_probe()[0])

    def test_no_previous_cycle_no_address(self):
        self.assertIsNone(self._engine()._claim_tunnel_probe()[0])

    def test_the_feature_alone_does_not_open_the_gate(self):
        self.assertIsNone(self._engine(self._down(), consent=False)._claim_tunnel_probe()[0])

    def test_the_consent_alone_does_not_open_the_gate(self):
        self.assertIsNone(self._engine(self._down(), feature=False)._claim_tunnel_probe()[0])

    def test_revoking_the_consent_closes_it_again(self):
        eng = self._engine(self._down())
        self.assertEqual(eng._claim_tunnel_probe()[0], ENDPOINT)
        eng.cfg.revoke("external_probes")
        self.assertIsNone(eng._claim_tunnel_probe()[0])

    def test_a_hostile_address_never_becomes_a_target(self):
        eng = self._engine(self._down(reason="No Network via 127.0.0.1:2408"))
        self.assertIsNone(eng._claim_tunnel_probe()[0])


class TestTheProbeCap(unittest.TestCase):
    """**한 공급자의 한 끊김에 최대 12발** (AC-4 수정분, 사용자 결정 2026-09-22).

    67분짜리 끊김에서 수백 발이 제3자에게 나가는 일을 막는다. 세는 단위는
    공급자 하나의 끊김 하나이고, 그 공급자가 다시 연결되면 0 부터 센다.

    **부르는 것이 곧 예산을 쓰는 것이다** — `_claim_tunnel_probe()` 는 보내기로
    정하면서 그 발 수를 센다. 아래에서 한 테스트가 여러 번 부르는 것은 여러
    주기를 흉내 내는 것이다.
    """

    def _engine(self, state=None, last_vpn=None, ping_count=None):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        cfg = configmod.load(os.path.join(d, "config.json"))
        cfg.grant("external_probes", note="테스트")
        cfg.set_feature("vpn.tunnel_probe", True)
        if ping_count is not None:
            cfg.data["ping_count"] = ping_count
        eng = Engine.__new__(Engine)
        eng.cfg = cfg
        eng.state = {} if state is None else state
        eng._last_vpn = last_vpn if last_vpn is not None else helpers.vpn_state(
            "disconnected", reason=helpers.ENDPOINT_REASON)
        return eng

    def _counts(self, eng):
        return eng.state.get(enginemod.ENDPOINT_PROBES_KEY)

    def test_the_cap_is_twelve(self):
        self.assertEqual(vpnmod.TUNNEL_PROBE_CAP, 12)

    def test_twelve_go_out_and_the_thirteenth_does_not(self):
        eng = self._engine()
        for i in range(12):
            self.assertEqual(eng._claim_tunnel_probe(), (ENDPOINT, False), i)
        self.assertEqual(eng._claim_tunnel_probe(), (None, True))
        self.assertEqual(eng._claim_tunnel_probe(), (None, True))
        self.assertEqual(self._counts(eng),
                         {"warp": {"shots": 12, "capped": True}})

    def test_the_cap_counts_packets_not_cycles(self):
        """한 주기에 나가는 발 수는 `ping_count` 에 달렸다 (AC-4 는 "12발").

        주기를 세면 `ping_count` 를 올려 둔 사람에게는 12발보다 많이 나간다
        — 엔드포인트는 대상이 하나라 한 주기에 `ping_count` 발이 나간다
        (`collect/link.collect` 의 `per = 1 if n > 1 else count`).
        """
        eng = self._engine(ping_count=3)
        for i in range(4):
            self.assertEqual(eng._claim_tunnel_probe(), (ENDPOINT, False), i)
        self.assertEqual(eng._claim_tunnel_probe(), (None, True))
        self.assertEqual(self._counts(eng)["warp"]["shots"], 12)

    def test_a_ping_count_over_the_cap_sends_nothing_and_says_so(self):
        """상한을 넘겨 보내느니 재지 않는다. 그 사실은 표시로 남는다."""
        eng = self._engine(ping_count=13)
        self.assertEqual(eng._claim_tunnel_probe(), (None, True))
        self.assertEqual(self._counts(eng), {"warp": {"shots": 0, "capped": True}})

    def test_a_broken_ping_count_is_read_as_one(self):
        eng = self._engine(ping_count="많이")
        self.assertEqual(eng._claim_tunnel_probe(), (ENDPOINT, False))
        self.assertEqual(self._counts(eng)["warp"]["shots"], 1)

    def test_the_count_is_where_a_restart_can_find_it(self):
        """launchd 가 되살려도 상한이 남아 있어야 한다.

        메모리에 두면 재시작마다 0 이 되어 긴 끊김에서 상한이 사실상
        없어진다. 그래서 `state.json` 에 둔다.
        """
        eng = self._engine()
        for _ in range(12):
            eng._claim_tunnel_probe()
        restarted = self._engine(state=dict(eng.state))
        self.assertEqual(restarted._claim_tunnel_probe(), (None, True))

    def test_it_works_without_the_key(self):
        """키가 없거나 이상한 값이어도 0 부터 센다 (상태 파일 규칙).

        정수 하나였던 옛 모양도 여기에 든다 — 그 판은 공급자를 가리지 않고
        하나로 셌다.
        """
        KEY = enginemod.ENDPOINT_PROBES_KEY
        for state in ({}, {KEY: "많이"}, {KEY: None}, {KEY: True}, {KEY: 12},
                      {KEY: {"warp": 12}}, {KEY: {"warp": None}},
                      {KEY: {"warp": {"shots": "많이"}}}):
            eng = self._engine(state=dict(state))
            self.assertEqual(eng._claim_tunnel_probe(), (ENDPOINT, False), state)

    def test_reconnecting_starts_the_count_again(self):
        eng = self._engine()
        for _ in range(12):
            eng._claim_tunnel_probe()
        self.assertEqual(eng._claim_tunnel_probe(), (None, True))

        eng._last_vpn = helpers.vpn_state("connected")
        self.assertEqual(eng._claim_tunnel_probe(), (None, False))
        self.assertNotIn(enginemod.ENDPOINT_PROBES_KEY, eng.state)

        eng._last_vpn = helpers.vpn_state("disconnected",
                                          reason=helpers.ENDPOINT_REASON)
        for i in range(12):
            self.assertEqual(eng._claim_tunnel_probe(), (ENDPOINT, False), i)
        self.assertEqual(eng._claim_tunnel_probe(), (None, True))

    def test_a_provider_that_is_always_unknown_does_not_eat_the_budget(self):
        """늘 `unknown` 인 공급자가 있어도 상한은 "한 끊김" 으로 남는다.

        `MacOSNative` 는 직접 담당할 서비스가 없으면 설계상 늘 `unknown` 을
        돌려주고(`vpn/__init__.py` 의 "직접 담당할 서비스 없음"), `scutil` 은
        모든 맥에 있어 기본 설정에서 그 공급자가 늘 목록에 든다. 창을
        "아무 공급자나 비connected" 로 세면 창이 영영 닫히지 않아, 첫 12발을
        쓰고 나면 **그 뒤의 어떤 끊김에서도 한 발도 나가지 않았다**
        (검수 1차 지적).
        """
        def block(warp_state):
            out = {"macos": {"provider": "macos", "state": "unknown",
                             "reason": "직접 담당할 서비스 없음 (전용 공급자가 처리)"}}
            out.update(helpers.vpn_state(warp_state,
                                         reason=helpers.ENDPOINT_REASON))
            return out

        eng = self._engine(last_vpn=block("disconnected"))
        for _ in range(12):
            eng._claim_tunnel_probe()
        self.assertEqual(eng._claim_tunnel_probe(), (None, True))

        # 끊김이 끝났다. 늘 unknown 인 공급자가 옆에 있어도 창이 닫힌다.
        eng._last_vpn = block("connected")
        self.assertEqual(eng._claim_tunnel_probe(), (None, False))
        self.assertNotIn(enginemod.ENDPOINT_PROBES_KEY, eng.state)

        # 다음 끊김에서는 다시 잰다 — 이 작업이 만들려는 근거가 그 시점부터
        # 수집되지 않는 것이 고치기 전의 결함이었다.
        eng._last_vpn = block("disconnected")
        self.assertEqual(eng._claim_tunnel_probe(), (ENDPOINT, False))

    def test_a_failed_provider_query_does_not_refill_the_cap(self):
        """`unknown` 주기는 보내지도 않고 세던 것을 버리지도 않는다.

        버리면 조회가 간헐적으로 실패하는 동안 상한이 계속 되살아난다.
        """
        eng = self._engine()
        for _ in range(12):
            eng._claim_tunnel_probe()
        eng._last_vpn = helpers.vpn_state("unknown",
                                          reason=helpers.ENDPOINT_REASON)
        self.assertEqual(eng._claim_tunnel_probe(), (None, False))
        eng._last_vpn = helpers.vpn_state("disconnected",
                                          reason=helpers.ENDPOINT_REASON)
        self.assertEqual(eng._claim_tunnel_probe(), (None, True))

    def test_a_missing_vpn_block_does_not_refill_the_cap(self):
        """수집이 통째로 실패한 주기도 "연결됐다" 가 아니다."""
        eng = self._engine()
        for _ in range(12):
            eng._claim_tunnel_probe()
        eng._last_vpn = {}
        self.assertEqual(eng._claim_tunnel_probe(), (None, False))
        eng._last_vpn = helpers.vpn_state("disconnected",
                                          reason=helpers.ENDPOINT_REASON)
        self.assertEqual(eng._claim_tunnel_probe(), (None, True))

    def test_each_provider_has_its_own_budget(self):
        """한 공급자가 예산을 다 써도 다른 공급자의 끊김은 그대로 잰다."""
        other = "No Network via 203.0.113.9:2408"
        eng = self._engine(last_vpn=helpers.vpn_state(
            "disconnected", reason=helpers.ENDPOINT_REASON))
        for _ in range(12):
            eng._claim_tunnel_probe()
        self.assertEqual(eng._claim_tunnel_probe(), (None, True))

        eng._last_vpn = helpers.vpn_state("disconnected", reason=other,
                                          provider="tailscale")
        self.assertEqual(eng._claim_tunnel_probe(), ("203.0.113.9", False))
        self.assertEqual(self._counts(eng)["tailscale"]["shots"], 1)
        self.assertEqual(self._counts(eng)["warp"]["shots"], 12)

    def test_a_cycle_without_an_address_is_not_counted(self):
        """주소를 못 고른 주기는 보내지 않은 주기다."""
        eng = self._engine(last_vpn=helpers.vpn_state("disconnected",
                                                      reason="No Network"))
        for _ in range(20):
            self.assertEqual(eng._claim_tunnel_probe(), (None, False))
        self.assertNotIn(enginemod.ENDPOINT_PROBES_KEY, eng.state)

    def test_a_closed_gate_never_counts_or_caps(self):
        """동의가 없으면 세지도 않고 상한 표시도 만들지 않는다 (ADV-5)."""
        eng = self._engine()
        eng.cfg.revoke("external_probes")
        for _ in range(20):
            self.assertEqual(eng._claim_tunnel_probe(), (None, False))
        self.assertNotIn(enginemod.ENDPOINT_PROBES_KEY, eng.state)

    def test_the_first_cycle_of_a_process_does_not_touch_the_count(self):
        """직전 주기가 아직 없는 주기는 "끊김이 끝났다" 가 아니다.

        `_last_vpn` 은 `observe()` 끝에서야 채워지므로 새 프로세스의 첫
        주기에는 없다. 여기서 기록을 지우면 launchd 가 되살릴 때마다 12발이
        새로 채워진다 (검수 1차 지적). `observe()` 를 통째로 돌리는 확인은
        TestEnginePassesBothGatesToTheCollector 에 있다.
        """
        saved = {"warp": {"shots": 12, "capped": True}}
        eng = self._engine(state={enginemod.ENDPOINT_PROBES_KEY: dict(saved)})
        del eng._last_vpn  # 클래스 기본값(None)으로 되돌린다 = 첫 주기
        self.assertEqual(eng._claim_tunnel_probe(), (None, False))
        self.assertEqual(self._counts(eng), saved)


class TestEnginePassesBothGatesToTheCollector(unittest.TestCase):
    """엔진이 수집기에 넘기는 ctx 키가 실제로 맞물리는가 (QA-5, QA-22).

    수집기는 `allow_tunnel_probe` 와 `tunnel_endpoint` 를 본다. 이름이 어긋나면
    기능이 조용히 죽거나(꺼짐) 조용히 산다(켜짐) — 어느 쪽도 로그에 남지 않는다.
    그래서 `observe()` 를 한 번 돌려 무엇이 넘어가는지 본다. 수집기는 전부
    가짜라 명령이 실행되지 않는다.
    """

    def _observe(self, consent=True, feature=True, last_vpn=None,
                 vpn_now=None, state=None):
        from netmon.collect import arp, dhcp, dns, iface, route, wifi

        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        cfg = configmod.load(os.path.join(d, "config.json"))
        if consent:
            cfg.grant("external_probes", note="테스트")
        cfg.set_feature("vpn.tunnel_probe", feature)
        eng = Engine.__new__(Engine)
        eng.cfg = cfg
        eng.state = {} if state is None else state
        eng.needs = {}
        eng.prev = None
        eng.prev_wall = None
        eng._arp_log_read_at = None
        if last_vpn is not None:
            # **넘기지 않으면 세팅하지 않는다.** 새 프로세스의 첫 주기에는
            # `_last_vpn` 이 아예 없다(클래스 기본값 None) — 그 주기를
            # 모사하려면 여기서 대신 채워 주면 안 된다 (검수 1차 지적).
            eng._last_vpn = last_vpn
        seen = {}

        def fake_link_collect(ctx):
            seen.update(ctx)
            return {}

        with contextlib.ExitStack() as stack:
            for mod in (iface, arp, dhcp, route, dns, wifi):
                stack.enter_context(mock.patch.object(mod, "collect",
                                                      lambda ctx=None: {}))
            stack.enter_context(mock.patch.object(first_hop, "collect",
                                                  fake_link_collect))
            if vpn_now is not None:
                # 이번 주기의 VPN 상태를 정해 준다. 공급자 조회는 하지 않는다.
                cfg.set_feature("vpn.enabled", True)
                stack.enter_context(mock.patch.object(vpnmod, "resolve",
                                                      lambda names: []))
                stack.enter_context(mock.patch.object(vpnmod, "collect",
                                                      lambda providers: vpn_now))
            self.obs = eng.observe()
        return seen

    def test_the_address_and_the_gate_both_reach_the_collector(self):
        seen = self._observe(last_vpn=helpers.vpn_state(
            "disconnected", reason=helpers.ENDPOINT_REASON))
        self.assertTrue(seen["allow_tunnel_probe"])
        self.assertEqual(seen["tunnel_endpoint"], ENDPOINT)

    def test_without_consent_the_collector_gets_nothing_to_send(self):
        seen = self._observe(consent=False, last_vpn=helpers.vpn_state(
            "disconnected", reason=helpers.ENDPOINT_REASON))
        self.assertFalse(seen["allow_tunnel_probe"])
        self.assertIsNone(seen["tunnel_endpoint"])

    def test_one_probe_still_goes_out_right_after_reconnecting(self):
        """방아쇠가 직전 주기 기준이라 재접속 직후 첫 주기에도 한 번 나간다.

        이번 주기의 VPN 상태는 이 결정을 내릴 때 아직 없다 — link 가 vpn
        보다 먼저 돌기 때문이다(`netmon/engine.py` 의 수집 순서). 문구가
        이 사실을 적어야 하므로(AC-4 수정분 (d)) 동작으로 고정해 둔다.
        """
        seen = self._observe(
            last_vpn=helpers.vpn_state("disconnected",
                                       reason=helpers.ENDPOINT_REASON),
            vpn_now=helpers.vpn_state("connected"))
        self.assertEqual(seen["tunnel_endpoint"], ENDPOINT)
        # 이번 주기의 관측에는 이미 connected 로 적힌다.
        self.assertEqual(self.obs.data["vpn"]["warp"]["state"], "connected")

    def test_a_capped_cycle_reaches_the_collector_as_a_mark(self):
        """상한에 닿은 주기는 주소 없이 '상한' 표시만 넘어간다."""
        eng_state = {enginemod.ENDPOINT_PROBES_KEY:
                     {"warp": {"shots": vpnmod.TUNNEL_PROBE_CAP, "capped": True}}}
        seen = self._observe(last_vpn=helpers.vpn_state(
            "disconnected", reason=helpers.ENDPOINT_REASON), state=eng_state)
        self.assertIsNone(seen["tunnel_endpoint"])
        self.assertTrue(seen["tunnel_probe_capped"])

    def test_the_first_cycle_after_a_restart_keeps_the_count_on_disk(self):
        """새 프로세스의 첫 주기가 디스크에서 읽어 온 카운터를 지우지 않는다.

        `_last_vpn` 은 `observe()` **끝**에서 채워지는데 `observe()` 는 맨 첫
        줄에서 이 판단을 한다. 그래서 첫 주기는 늘 "직전 주기가 없다" 이고,
        그것을 "끊김이 끝났다" 로 읽으면 launchd 가 되살릴 때마다 12발이
        새로 채워진다 — 카운터를 `state.json` 에 둔 까닭이 바로 그 경로에서
        무너진다 (검수 1차 지적). 여기서는 `_last_vpn` 을 **세팅하지 않고**
        `observe()` 를 돌려 실제 첫 주기를 그대로 모사한다.
        """
        saved = {"warp": {"shots": vpnmod.TUNNEL_PROBE_CAP, "capped": True}}
        state = {enginemod.ENDPOINT_PROBES_KEY: dict(saved)}
        seen = self._observe(state=state)
        # 그 주기에는 어차피 주소가 없다. 아무것도 나가지 않는다.
        self.assertIsNone(seen["tunnel_endpoint"])
        self.assertFalse(seen["tunnel_probe_capped"])
        # **값으로 확인한다** — 디스크에서 읽어 온 카운터가 그대로 있어야 한다.
        self.assertEqual(state[enginemod.ENDPOINT_PROBES_KEY], saved)

        # 그다음 주기(직전 주기가 생긴 뒤)에는 상한이 그대로 걸린다.
        seen = self._observe(state=state, last_vpn=helpers.vpn_state(
            "disconnected", reason=helpers.ENDPOINT_REASON))
        self.assertIsNone(seen["tunnel_endpoint"])
        self.assertTrue(seen["tunnel_probe_capped"])


# --- 실행되지 못한 탐침 (DEV-10, AC-10) ---------------------------------
#
# 아래 두 클래스는 **`util.run` 이 실제로 돌려주는 모양**으로 판정한다.
# CmdResult 를 손으로 지어내면 실제 실패 경로(`FileNotFoundError` 갈래가
# not_found 와 rc 를 함께 세우는 것 등)가 바뀌어도 통과해 버린다.

MISSING_COMMAND = ["netmon-no-such-command-for-tests"]


@contextlib.contextmanager
def a_file_without_the_execute_bit():
    d = tempfile.mkdtemp()
    try:
        path = os.path.join(d, "ping")
        with open(path, "w") as fh:
            fh.write("#!/bin/sh\nexit 0\n")
        os.chmod(path, 0o644)
        yield path
    finally:
        shutil.rmtree(d, ignore_errors=True)


class TestTheShapesRunReallyReturns(unittest.TestCase):
    """`util.run` 의 실패 갈래 세 가지. 네트워크로 아무것도 보내지 않는다."""

    def test_a_command_that_is_not_there(self):
        r = util.run(MISSING_COMMAND)
        self.assertTrue(r.not_found)
        self.assertEqual(r.rc, 127)
        self.assertEqual(r.out, "")
        self.assertFalse(r.ok)

    def test_a_command_that_cannot_be_executed(self):
        with a_file_without_the_execute_bit() as path:
            r = util.run([path])
        self.assertEqual(r.rc, 126)
        self.assertFalse(r.not_found)
        self.assertFalse(r.timed_out)
        self.assertEqual(r.out, "")

    def test_a_command_that_outlives_its_limit(self):
        r = util.run(["sleep", "5"], timeout=0.05)
        self.assertTrue(r.timed_out)
        self.assertEqual(r.out, "")

    def test_a_silent_ping_is_not_one_of_those(self):
        """응답이 없는 ping 도 rc 는 0 이 아니다 — 실행은 됐다."""
        r = CmdResult(["ping", GW], 2, LOST, "")
        self.assertFalse(r.ok)
        self.assertFalse(r.not_found)
        self.assertFalse(r.timed_out)


def ping_through(real_argv, limit=None, target=GW):
    """`ping()` 을 `util.run` 의 **진짜 실패 결과**로 돌린다.

    ping 명령은 실행하지 않는다. 대신 실패하는 다른 명령(없는 명령, 실행
    권한이 없는 파일, 시간을 넘기는 sleep)을 실제로 돌려 그 CmdResult 를
    ping 자리에 넣는다.
    """
    def fake(argv, timeout=None, stdin=""):
        # 제한 시간은 이 시험이 정한다 — ping 의 4초를 실제로 기다리지 않는다.
        return util.run(real_argv, timeout=limit) if limit else util.run(real_argv)

    with mock.patch.object(first_hop, "run", fake):
        return first_hop.ping(target)


class TestAProbeThatCouldNotRunSaysSo(unittest.TestCase):
    """나가지 않은 패킷을 무응답으로 적지 않는다 (DEV-10, AC-10).

    `ping()` 이 `run` 의 rc·timed_out·not_found 를 버리면, 명령을 찾지
    못한 주기도 `{replies: 0, loss_pct: 100.0, reachable: False}` 로만 나와
    판정이 그것을 "무응답" 으로 읽는다. 관측에 남는 신호는 기존 `error`
    키다 — 새 키를 만들지 않는다.
    """

    def test_a_missing_binary_is_recorded_as_not_run(self):
        out = ping_through(MISSING_COMMAND)
        self.assertEqual(out["error"], PROBE_NOT_RUN)
        self.assertFalse(out["reachable"])

    def test_a_binary_that_cannot_be_executed_is_recorded_as_not_run(self):
        with a_file_without_the_execute_bit() as path:
            out = ping_through([path])
        self.assertEqual(out["error"], PROBE_NOT_RUN)

    def test_a_timeout_is_recorded_as_a_different_thing(self):
        """"실행되지 못함" 과 "끝나지 못함" 은 뜻이 다르다."""
        out = ping_through(["sleep", "5"], limit=0.05)
        self.assertEqual(out["error"], PROBE_TIMED_OUT)
        self.assertNotEqual(PROBE_TIMED_OUT, PROBE_NOT_RUN)

    def test_a_silent_but_real_ping_carries_no_error(self):
        """가드가 넘치지 않는다 — 무응답 주기는 rc 가 0 이 아니어도 실행됐다."""
        fake = FakeRun(outs=[LOST], rc=2)
        with mock.patch.object(first_hop, "run", fake):
            out = first_hop.ping(GW)
        self.assertNotIn("error", out)
        self.assertEqual(out["loss_pct"], 100.0)
        self.assertFalse(out["reachable"])

    def test_an_answered_ping_keeps_its_shape(self):
        with mock.patch.object(first_hop, "run", FakeRun()):
            out = first_hop.ping(GW)
        self.assertEqual(set(out),
                         {"rtt_ms", "rtt_max_ms", "loss_pct", "replies", "reachable"})

    def test_the_note_is_a_fixed_word_without_the_target(self):
        """터널 엔드포인트에도 같은 문구가 쓰인다 — 주소가 섞이면 안 된다.

        `_error_note` 가 엔드포인트에 두는 제약(고정된 낱말, 주소 불포함)을
        여기서도 지킨다. 권한 오류 메시지에는 실행 파일 경로가 들어 있다.
        """
        with a_file_without_the_execute_bit() as path:
            out = ping_through([path], target=helpers.ENDPOINT)
            self.assertNotIn(path, repr(out))
        self.assertNotIn(helpers.ENDPOINT, repr(out))
        self.assertIn(out["error"], (PROBE_NOT_RUN, PROBE_TIMED_OUT))

    def test_the_whole_cycle_carries_the_failure(self):
        """수집기를 통과해도 남는다. 다발은 합쳐진 `errors` 로 실린다."""
        def fake(argv, timeout=None, stdin=""):
            return util.run(MISSING_COMMAND)
        with mock.patch.object(first_hop, "run", fake):
            single = first_hop.collect({"gateway": GW})
            burst = first_hop.collect({"gateway": GW, "first_hop_burst": True,
                                       "interval": 5})
        self.assertEqual(single["results"]["gateway"]["error"], PROBE_NOT_RUN)
        self.assertEqual(burst["results"]["gateway"]["errors"], [PROBE_NOT_RUN])
        self.assertEqual(burst["results"]["gateway"]["sent"], 3)

    def test_the_endpoint_result_carries_it_without_the_address(self):
        """엔드포인트 결과에도 주소가 섞이지 않는다 (DEV-10 4번)."""
        with a_file_without_the_execute_bit() as path:
            def fake(argv, timeout=None, stdin=""):
                return util.run([path])
            with mock.patch.object(first_hop, "run", fake):
                block = first_hop.collect({"gateway": GW,
                                           "allow_tunnel_probe": True,
                                           "tunnel_endpoint": helpers.ENDPOINT})
            got = block["results"][first_hop.TUNNEL_ENDPOINT]
            self.assertEqual(got["error"], PROBE_NOT_RUN)
            self.assertNotIn(path, repr(got))
        self.assertNotIn(helpers.ENDPOINT, repr(got))


if __name__ == "__main__":
    unittest.main()
