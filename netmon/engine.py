"""수집 → 판정 → 저장을 잇는 한 주기.

수집기 실행 순서에 의존이 있다. iface 가 주 인터페이스와 게이트웨이를
정해야 나머지가 무엇을 볼지 알고, dns 가 리졸버를 알려줘야 link 가
측정 대상을 정한다.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple

from . import baseline, investigate, liveness, messages, vpn
from .collect import arp, dhcp, dns, iface, link, route, wifi
from .config import Config
from .detect import quality
# 수집기 `netmon.vpn` 과 이름이 겹쳐 별칭으로 부른다.
from .detect import vpn as vpn_detect
from .detect import (Context, associated_without_ipv4, attributions_for, gap_exceeded,
                     is_complete, network_key,
                     run_all)
from . import messages as msg
from .model import CONFIRMED, INFO, INFO_SEV, Finding, Observation, unwrap
from .store import Store
from .util import ts_now


def _external_resolver(dns_block: Dict[str, Any]) -> Optional[str]:
    """루프백이 아닌 첫 리졸버. 없으면 None."""
    from .collect.dns import is_loopback
    for r in dns_block.get("resolvers") or []:
        addr = unwrap(r)
        if addr and not is_loopback(str(addr)):
            return str(addr)
    return None


def _collect_error(exc: Exception) -> str:
    """수집기가 던진 예외를 관측에 남길 문구로. **예외 종류 이름까지다.**

    `str(exc)` 를 싣지 않는다. `Observation.errors` 는 그대로 직렬화되고
    (netmon/model.py 의 `as_dict`), `capture` 는 그 결과를 파일로 내보낸다.
    `--redact` 는 `ident()` 로 감싼 값만 바꾸므로(netmon/redact.py) 감싸지
    않은 문장은 내보낼 때도 가려지지 않는다. 그런데 subprocess 는 실행 실패
    예외에 **실행 파일 경로**를 담는다(CPython subprocess.py 의
    `err_filename = orig_executable`; 실측 `[Errno 8] Exec format error:
    '<경로>/netmon-not-a-binary'`). `util.run` 이 잡는 것은 FileNotFoundError·
    PermissionError·TimeoutExpired 뿐이라 그런 OSError 는 여기까지 올라온다.

    `ident()` 로 감싸지 않는 이유는 collect/link.py 의 `_error_note` 와 같다 —
    여기 오는 것은 경로 하나가 아니라 **문장**이라 `ID_KINDS` 의 어느 종류에도
    맞지 않고(`path` 종류는 있으나 경로 값에 붙이는 이름이다 — netmon/model.py),
    문장째 감싸면 `redact` 가 전체를 토큰 하나로 바꿔 오류 내용이 사라진다.

    잃는 것은 예외 메시지의 진단 정보다. 어느 갈래였는지는 종류 이름으로
    가릴 수 있고, 흔한 실패(명령 없음·권한·제한 시간)는 `util.run` 이 이미
    잡아 수집기가 고정 낱말로 적는다. 종류 이름은 비어 있는 법이 없으므로
    "오류가 있었다" 는 사실 자체도 그대로 남는다.
    """
    return type(exc).__name__


# 비교 기준을 디스크에 남기는 주기. 매 주기 쓰면 쓰기량이 20배가 된다.
BASELINE_SAVE_SECONDS = 60.0

# 이 끊김에 터널 엔드포인트로 몇 발 나갔는가. 상한(vpn.TUNNEL_PROBE_CAP)을
# 세는 자리이고, 모양은 `{공급자: {"shots": 발 수, "capped": 상한에 닿았는가}}`
# 다 — 세는 단위가 공급자 하나의 끊김 하나이기 때문이다(vpn.carry_probe_counts).
# **없어도 동작한다** — 없거나 모양이 다르면 0 부터 센다.
#
# 이름은 `netmon/vpn` 것을 그대로 쓴다. 여기서 쓰고 복구 판정이 읽으므로
# (netmon/detect/vpn.py `_endpoint_probe_record`) 한 곳에서 와야 한다.
ENDPOINT_PROBES_KEY = vpn.ENDPOINT_PROBES_KEY

# 커널 ARP 로그를 읽는 간격과 조회 창. `log show` 는 고정 1초쯤 들고 창이
# 커지면 더 든다(1시간치 8.9초). 간격보다 창을 넉넉히 잡아 빈틈을 막는다.
ARP_LOG_EVERY_SECONDS = 60.0
ARP_LOG_WINDOW_SECONDS = 90.0


class Engine:
    # 첫 홉 다발 측정을 켤지 정하는 직전 주기의 관측. 클래스 기본값으로 두는
    # 것은 replay() 가 __init__ 을 우회하기 때문이다.
    _last_link: Optional[Dict[str, Any]] = None
    _last_arp: Optional[Dict[str, Any]] = None
    _last_vpn: Optional[Dict[str, Any]] = None
    _before_vpn: Optional[Dict[str, Any]] = None
    # **직전 주기**의 VPN 블록. 위의 `_last_vpn` 과 달리 판정 단계에서
    # 갱신되므로, 수집을 거치지 않는 replay() 에서도 같은 값이 된다.
    # 판정하지 않은 주기(링크 없음)도 여기에는 남는다 — 링크가 없는 동안
    # 끊긴 순간을 볼 수 있는 유일한 비교 대상이다.
    _prev_cycle_vpn: Optional[Dict[str, Any]] = None

    def __init__(self, cfg: Config, store: Store) -> None:
        self.cfg = cfg
        self.store = store
        messages.use_config(cfg.language)
        self.prev: Optional[Observation] = None
        # 주 인터페이스가 있던 마지막 관측. 정체성 비교의 기준점이다 —
        # 링크가 끊긴 동안의 빈 관측과 비교하면 정체성이 두 번 뒤집힌다.
        self.anchor: Optional[Observation] = None
        # 판정할 수 없는 주기를 지나왔는가. 다음 완전한 관측이 그것을
        # "링크가 새로 붙었다" 로 읽을 근거가 된다.
        self.link_gap: bool = False
        self.prev_wall: Optional[float] = None
        self.state: Dict[str, Any] = store.load_state()
        # **비교 기준을 디스크에서 되살린다.** 이것이 없으면 재시작 경계에
        # 걸친 변화가 통째로 사라진다 — 게이트웨이 MAC 과 DHCP 서버가 동시에
        # 바뀌어도 판정이 하나도 나지 않는 것을 실험으로 확인했다.
        # launchd 가 KeepAlive 로 되살리므로 의도치 않은 재시작도 잦다.
        self._baseline_saved_at: Optional[float] = None
        self._arp_log_read_at: Optional[float] = None
        self._restore_baseline()
        self.investigator = investigate.Investigator(cfg.data.get("investigate"))
        # 조사가 요청한 측정 변화. 다음 주기에 반영된다.
        self.needs: Dict[str, Any] = {}

    # --- 재시작을 건너뛰는 비교 기준 ---
    def _restore_baseline(self) -> None:
        saved = self.store.load_baseline()
        if not isinstance(saved, dict) or not saved.get("ts"):
            return
        try:
            obs = Observation(ts=saved["ts"], data=saved.get("data") or {})
        except Exception:
            return
        if not is_complete(obs):
            return
        self.prev = obs
        self.anchor = obs
        wall = saved.get("wall")
        self.prev_wall = float(wall) if isinstance(wall, (int, float)) else None
        # 에이전트가 멈춰 있던 시간은 측정 공백이다. 다음 주기에서 elapsed 가
        # 크게 벌어져 sleep 으로 귀속되는데, sleep 은 품질만 설명하고
        # 정체성 판정은 그대로 판정된다 — 원하는 동작이다.

    def _keep_baseline(self, obs: Observation, wall: Optional[float]) -> None:
        """기준을 디스크에 남긴다. 매 주기 쓰지 않는다 — 60초면 충분하다.

        재시작이 기준을 60초까지 뒤처진 것으로 만들 수 있으나, 그 기준으로도
        보안 비교는 그대로 성립한다. 아무것도 없는 것과는 전혀 다르다.
        """
        if not is_complete(obs):
            return
        last = self._baseline_saved_at
        if last is not None and wall is not None and wall - last < BASELINE_SAVE_SECONDS:
            return
        self.store.save_baseline({"ts": obs.ts, "data": obs.data, "wall": wall})
        self._baseline_saved_at = wall

    # --- 수집 ---
    def observe(self) -> Observation:
        obs = Observation(ts=ts_now())
        endpoint, endpoint_capped = self._claim_tunnel_probe()
        ctx: Dict[str, Any] = {
            "allow_location": self.cfg.effective("detect.evil_twin"),
            "allow_external": self.cfg.effective("detect.public_ip"),
            "config_home": os.path.dirname(self.cfg.path),
            "wifi_helper_interval": self.cfg.data.get("wifi_helper_interval", 15),
            "ping_count": self.cfg.data.get("ping_count", 1),
            # 조사 중에는 주기가 좁혀진다. 다발 측정은 그 주기 안에 들어갈 때만 한다.
            "interval": self.effective_interval(self.cfg.interval),
            # **직전 주기**의 관측으로만 정한다. 같은 주기의 VPN 상태는 아직 없다 —
            # link 가 vpn 보다 먼저 돌기 때문이다.
            "first_hop_burst": self._burst_hint(),
            # 터널 엔드포인트 측정. 동의와 기능이 함께 켜졌을 때만 참이고,
            # 주소는 직전 주기의 VPN 관측에서 온다. 둘 중 하나라도 없으면
            # 수집기는 대상을 만들지 않는다 (netmon/collect/link.py).
            "allow_tunnel_probe": self.cfg.effective("vpn.tunnel_probe"),
            "tunnel_endpoint": endpoint,
            # 상한에 닿아 보내지 않은 주기임을 관측에 남기려고 함께 넘긴다.
            # 주소가 없어서 재지 않은 주기와 구분되지 않으면, 나중에 기록을
            # 읽는 쪽이 "안 보냈다" 의 이유를 알 수 없다.
            "tunnel_probe_capped": endpoint_capped,
        }

        def step(module, name: str) -> None:
            try:
                obs.data[name] = module.collect(ctx)
            except Exception as exc:
                # 예외 **메시지**는 옮기지 않는다 — 경로가 섞여 나오고, 감싸지
                # 않은 문자열이라 `capture --redact` 에도 남는다(_collect_error).
                obs.errors[name] = _collect_error(exc)
                obs.data[name] = {}

        step(iface, "iface")
        ctx["primary"] = obs.data["iface"].get("primary")
        ctx["primary_kind"] = obs.data["iface"].get("primary_kind")
        # 주 인터페이스가 없을 때가 무선 상태를 가장 알고 싶은 순간이다.
        # 그런데 그때는 primary_kind 가 unknown 이라 wifi 수집기가 통째로
        # 건너뛰어서, "링크가 끊겼다" 고 적는 주기에 RSSI 도 link_active 도
        # 남지 않았다 (2026-09-21 확인).
        if not ctx["primary"]:
            ctx["wifi_fallback_dev"] = next(
                (p.get("dev") for p in (obs.data["iface"].get("ports") or [])
                 if p.get("kind") == "wifi"), None)
        gw = unwrap(obs.data["iface"].get("default4_gateway")) or \
            unwrap(obs.data["iface"].get("scoped_gateway"))
        ctx["gateway"] = gw

        # 커널 ARP 로그는 비싸다. 간격을 두고 읽는다.
        now_wall = self.prev_wall or 0.0
        due = (self._arp_log_read_at is None
               or now_wall - self._arp_log_read_at >= ARP_LOG_EVERY_SECONDS)
        ctx["read_arp_log"] = ARP_LOG_WINDOW_SECONDS if due else None
        if due:
            self._arp_log_read_at = now_wall
        step(arp, "arp")
        step(dhcp, "dhcp")
        # DHCP 가 정적 경로를 제공했으면 경로 수집기가 그 대역의 실제 송신
        # 인터페이스를 조회한다. 기본 경로만 봐서는 터널 우회가 보이지 않는다.
        ctx["dhcp_static_routes"] = ((obs.data["dhcp"].get("static_routes") or {})
                                     .get("routes") or [])
        step(route, "route")
        step(dns, "dns")
        # 헬퍼 앱 호출은 0.5초쯤 걸려서 매 주기 부르지 않는다. 다만 첫 주기이거나
        # L2·DHCP 가 흔들린 직후에는 바로 다시 읽는다 — evil twin 으로 옮겨 가는
        # 순간이 정확히 그 순간이기 때문이다.
        ctx["wifi_force_refresh"] = (self._wifi_changed_hint(obs)
                                     or bool(self.needs.get("open")))
        step(wifi, "wifi")

        ctx["resolver_external"] = _external_resolver(obs.data.get("dns", {}))
        step(link, "link")

        if self.cfg.feature("vpn.enabled"):
            providers = vpn.resolve(self.cfg.data.get("features", {}).get("vpn.providers", ["auto"]))
            try:
                obs.data["vpn"] = vpn.collect(providers)
            except Exception as exc:
                # 공급자 조회도 외부 명령을 쓴다. 위 `step` 과 같은 이유로
                # 종류 이름까지만 남긴다.
                obs.errors["vpn"] = _collect_error(exc)

        self._remember_for_burst(obs)
        return obs

    def _burst_hint(self) -> bool:
        """이번 주기의 첫 홉을 다발로 잴 것인가.

        판정 방법을 함께 넘긴다. ICMP 를 막아 둔 게이트웨이에서는
        `gateway_reachable` 이 정상 상태에도 매 주기 False 라, 그것만 보면
        아무 일도 없는데 주기마다 다발이 나간다 (netmon/collect/link.py).
        `self.state` 는 직전 주기까지의 보정 결과다 — 이번 주기 보정은
        판정 단계에서 일어나므로 여기서는 아직 반영돼 있지 않다.
        """
        return link.first_hop_anomaly(self._last_link, self._last_vpn,
                                      self._before_vpn,
                                      prev_arp=self._last_arp,
                                      method=liveness.method_for(self.state))

    def _claim_tunnel_probe(self) -> Tuple[Optional[str], bool]:
        """(이번 주기에 잴 주소, 상한에 닿아 보내지 않는 주기인가).

        **한 주기에 한 번만 부른다. 부르는 것이 곧 예산을 쓰는 것이다** —
        보내기로 정하면서 그 발 수를 세기 때문에, 조회하듯 다시 부르면 같은
        주기가 두 번 세진다. 그래서 값만 돌려주는 껍데기를 따로 두지 않는다.

        주소는 **직전 주기**의 VPN 관측에서 얻는다 — 같은 주기의 값은 아직
        없고(link 가 vpn 보다 먼저 돈다), 뒤에 직렬로 붙이면 한 주기가 약
        1.84초 길어져 조사 중 2~3초 주기를 넘긴다 (AC-4c). 그래서 끊김이
        시작된 첫 주기에는 주소가 없어 관측이 한 주기 늦게 시작된다.

        `self._last_vpn` 은 다발 측정 판단이 쓰는 것과 같은, 직전 주기의 VPN
        블록이다(`_remember_for_burst`). 링크가 없어 판정을 건너뛴 주기도
        여기에는 남는다 — VPN 상태는 링크가 없어도 수집되기 때문이다.

        세는 단위는 **공급자 하나의 끊김 하나**이고(`vpn.carry_probe_counts`),
        세는 것은 주기가 아니라 **발 수**다 — 한 주기에 나가는 발 수가
        `ping_count` 설정에 달렸기 때문이다(netmon/collect/link.py).

        센 값은 `state.json` 에 둔다. 메모리에 두면 launchd 가 되살릴 때마다
        0 이 되어(이 파일 위쪽 주석 — 의도치 않은 재시작이 잦다) 긴 끊김에서
        상한이 사실상 없어진다.

        **직전 주기가 아직 없으면(새 프로세스의 첫 주기) 아무것도 건드리지
        않는다.** "직전 주기가 없다" 와 "끊김이 끝났다" 는 다르다. 첫 주기에
        기록을 지우면 재시작할 때마다 상한이 새로 채워져, `state.json` 에
        둔 까닭이 바로 그 경로에서 무너진다. 그 주기에는 어차피 주소도 없다.
        """
        last = self._last_vpn
        if last is None:
            return None, False
        counts = vpn.carry_probe_counts(self.state.get(ENDPOINT_PROBES_KEY), last)
        self._save_probe_counts(counts)
        if not self.cfg.effective("vpn.tunnel_probe"):
            # 동의도 기능도 없으면 **주소를 고르지도 않는다.** 여기서 고른 값은
            # 수집기에 넘어가는 순간 송신 대상이 된다.
            return None, False
        # **주소를 먼저 고른다.** 상한을 먼저 보면, 보낼 주소가 없어서 어차피
        # 나가지 않았을 주기까지 "상한 때문에 안 보냄" 으로 적힌다. 고르는
        # 것만으로는 아무것도 나가지 않는다 (문자열 파싱이다).
        target = vpn.tunnel_probe_target(last)
        if target is None:
            # 고르지 못한 주기는 보내지 않은 주기다. 세지 않는다.
            return None, False
        name, addr = target
        sent = int(counts.get(name, {}).get("shots", 0))
        shots = self._endpoint_shots()
        if sent + shots > vpn.TUNNEL_PROBE_CAP:
            # 남은 예산이 이번 주기의 발 수를 못 받는다. 이 끊김에서는 더
            # 보내지 않는다 — 상한을 넘겨 보내느니 재지 않는 편이 낫다.
            counts[name] = {"shots": sent, "capped": True}
            self._save_probe_counts(counts)
            return None, True
        counts[name] = {"shots": sent + shots, "capped": False}
        self._save_probe_counts(counts)
        return addr, False

    def _save_probe_counts(self, counts: Dict[str, Dict[str, Any]]) -> None:
        """센 값을 상태에 남긴다. 셀 것이 없으면 키를 지운다.

        빈 dict 를 남기지 않는 것은 `state.json` 에 뜻 없는 키를 쌓지 않기
        위해서다. 읽는 쪽은 키가 없는 것과 빈 것을 같게 본다.
        """
        if counts:
            self.state[ENDPOINT_PROBES_KEY] = counts
        else:
            self.state.pop(ENDPOINT_PROBES_KEY, None)

    def _endpoint_shots(self) -> int:
        """엔드포인트 한 번 측정에 나가는 ICMP 발 수.

        **수집기가 쓰는 함수를 그대로 부른다.** 거기서는 대상이 하나라
        `per = count` 이고 그 `count` 가 `link.packets_per_command(ping_count)`
        다(netmon/collect/link.py). 여기서 따로 계산하면 — 예전에는
        `max(1, int(...))` 이었다 — 설정이 범위 밖일 때 세는 값과 실제로 나가는
        발 수가 어긋나고, 상한의 정확성이 그 일치에 기대고 있다.
        """
        return link.packets_per_command(self.cfg.data.get("ping_count", 1))

    def _remember_for_burst(self, obs: Observation) -> None:
        """다음 주기의 다발 측정 판단에 쓸, 직전 두 주기의 상태를 남긴다.

        링크가 없어 판정을 건너뛰는 주기도 여기서는 센다 — 첫 홉이 응답하지
        않은 주기가 바로 다음 주기를 다발로 재야 할 이유이기 때문이다.
        """
        self._before_vpn = self._last_vpn
        self._last_vpn = obs.get("vpn")
        self._last_link = obs.get("link")
        self._last_arp = obs.get("arp")

    def _wifi_changed_hint(self, obs: Observation) -> bool:
        if self.prev is None:
            return True
        for block, key in (("arp", "gateway_mac"), ("dhcp", "server_identifier"),
                           ("dhcp", "lease_start")):
            if unwrap(self.prev.get(block, key)) != unwrap(obs.get(block, key)):
                return True
        return False

    # --- 판정 ---
    def _detect_features(self) -> Dict[str, bool]:
        """판정기 기능 스위치. 동의까지 반영한 값이다."""
        return {k: self.cfg.effective(k) for k in self.cfg.data.get("features", {})
                if k.startswith("detect.")}

    def judge(self, obs: Observation, elapsed: float) -> List[Finding]:
        interval = float(self.cfg.interval)
        prev_vpn, self._prev_cycle_vpn = self._prev_cycle_vpn, obs.get("vpn")

        # **공백은 판정보다 먼저 귀속한다.** 이 주기에 VPN 복구 판정이 나면
        # 그 증거가 방금 지나간 공백까지 포함해야 한다. 판정 뒤에 더하면
        # 복구 주기 직전의 공백이 매번 빠진다.
        if gap_exceeded(elapsed, interval):
            # **한 주기분은 빼고 센다.** 이 도구가 약속하는 해상도가 한 주기이므로,
            # 정상 간격으로 돈 주기는 "측정됨" 이다. 공백 전체를 더하면 공백
            # 한 건마다 그만큼씩 미관측 시간이 부풀려진다.
            self.state = baseline.note_unmeasured(self.state, elapsed - interval)

        # 주 인터페이스가 없으면 비교할 상태가 아니다. 기록만 남기고 넘어간다.
        # 기준선도 건드리지 않는다 — 링크가 없는 동안의 값은 기준이 될 수 없다.
        if not is_complete(obs):
            self.link_gap = True
            iface = obs.get("iface") or {}
            summary = (msg.LINK_ABSENT_NO_IPV4 if associated_without_ipv4(iface)
                       else msg.LINK_ABSENT)
            out = [Finding(axis=INFO, kind="LINK_ABSENT", confidence=CONFIRMED,
                           severity=INFO_SEV, summary=summary,
                           evidence={"iface": iface},
                           network=self.state.get("network"))]
            # **판정은 건너뛰어도 공백은 남긴다.** 이 분기가 run_all 을 건너뛰는
            # 바람에, 주 인터페이스 없이 3시간 넘게 측정되지 않아도 이벤트에
            # 아무 흔적이 없었다 (2026-09-20 맥북, 공백의 98.9%).
            if self.prev is not None and gap_exceeded(elapsed, interval):
                gap = quality.measurement_gap(elapsed, interval)
                gap.network = self.state.get("network")
                out.append(gap)
            # **끊긴 시각은 이 주기에도 갱신한다.** VPN 상태는 링크가 없어도
            # 수집되는데 이 분기가 조기 반환하는 바람에 갱신되지 않았고,
            # 7분 25초 끊겨 있던 것이 복구 판정에 "5초" 로 적혔다
            # (2026-09-21 05:41~05:49 맥북).
            self.state = baseline.update_vpn_down(self.state, obs, judged=False)
            # **끊김 자체도 이 주기에 알린다.** 위 갱신만으로는 복구 판정의
            # 시작 시각이 맞아질 뿐, 끊긴 사실은 이벤트에 남지 않았다
            # (2026-09-21 링크 없는 끊김 4구간에 VPN 판정 0건).
            # 되살리는 것은 이 하나다 — `run_all` 은 여전히 돌지 않고,
            # 조사도 열지 않는다. 이 분기의 이유는 그대로다: 그 주기에
            # **관측이 없어서가 아니라**(수집 단계는 전부 돈다) 주 인터페이스가
            # 없는 주기의 경로·리졸버·ARP 가 "없음" 일 뿐이어서, 그대로 견주면
            # 링크가 깜빡일 때마다 바뀐 것처럼 보이기 때문이다
            # (netmon/detect 의 `is_complete`).
            #
            # 기능 스위치는 완전 주기와 **같은 눈**으로 읽는다. 설정에 없는
            # 이름은 켜진 것으로 본다(`Context.enabled` 와 같은 기본값) —
            # `detect.vpn` 은 config 기본값 목록에 없어서, 여기서만 다르게
            # 읽으면 평소 주기는 판정하는데 이 주기만 조용해진다.
            if self._detect_features().get(vpn_detect.FEATURE, True):
                found, self.state = vpn_detect.without_link(
                    prev_vpn, obs, self.state, self.state.get("network"))
                out.extend(found)
            return out

        link_gap = self.link_gap
        attributions = attributions_for(self.prev, obs, elapsed, interval,
                                        self.anchor, link_gap)
        self.link_gap = False
        # 링크가 새로 붙었으면 다른 장소일 수 있다. 이전 기준선을 그대로 쓰면
        # 새 장소의 첫 몇 분이 통째로 오탐이 된다.
        changed = any(a in attributions for a in
                      ("network_change", "iface_change", "link_restart"))
        if changed:
            self.state = baseline.reset_for_new_network(self.state)

        # 링크가 끊겼다 붙은 사실 자체로 안정화 창을 연다. SSID 를 알면
        # link_restart 는 귀속되지 않지만(정체성 검사를 지키려고), 재접속
        # 직후의 ARP 폭주와 리졸버 재설치는 SSID 를 알든 모르든 똑같이 일어난다.
        self.state = baseline.update_counters(self.state, obs, attributions,
                                              elapsed, interval,
                                              disrupted="link_restart" if link_gap else None)

        ctx = Context(
            elapsed=elapsed,
            interval=interval,
            features=self._detect_features(),
            state=self.state,
            attributions=attributions,
            network=network_key(obs),
        )
        findings = run_all(self.prev, obs, ctx)

        # 조사는 판정 뒤에 돈다. 이번 주기의 판정을 증거로 쓰기 때문이다.
        extra, self.needs = self.investigator.run(
            self.prev, obs, ctx, findings, self.state)
        findings.extend(extra)

        self.state = baseline.update_baselines(self.state, obs, elapsed, interval)
        self.state["network"] = ctx.network
        self.state["last_ts"] = obs.ts
        self.anchor = obs
        return findings

    # --- 한 주기 ---
    def cycle(self, now: Optional[float] = None) -> Tuple[Observation, List[Finding]]:
        import time
        now = now if now is not None else time.time()
        elapsed = (now - self.prev_wall) if self.prev_wall else 0.0
        obs = self.observe()
        findings = self.judge(obs, elapsed)
        # 판정할 수 없는 주기는 다음 비교의 기준이 되지 않는다.
        if is_complete(obs):
            self.prev = obs
        self.prev_wall = now
        # 다음 실행이 이어서 비교할 수 있도록 남긴다.
        self._keep_baseline(obs, now)
        return obs, findings

    def effective_interval(self, configured: float) -> float:
        """조사 중에는 더 자주 본다. 조사가 요청한 값과 설정값 중 짧은 쪽."""
        want = self.needs.get("interval")
        return min(float(configured), float(want)) if want else float(configured)

    def persist(self, obs: Observation, findings: List[Finding]) -> None:
        self.store.write_sample(obs)
        self.store.write_findings(obs.ts, findings)
        self.store.save_state(self.state)


def replay(cfg: Config, observations: List[Observation]) -> List[Tuple[Observation, List[Finding]]]:
    """캡처한 관측 열을 그대로 다시 판정한다. 네트워크가 필요 없다.

    현장에서 뜬 오탐을 집에서 재현하고, 고친 뒤 회귀로 남기는 데 쓴다.
    """
    import datetime

    # 저장소 없이 판정만 돌린다. __init__ 을 우회하므로 여기서 초기화하는 것을
    # 빠뜨리면 조용히 AttributeError 가 난다 — 실제로 조사 계층에서 그랬다.
    eng = Engine.__new__(Engine)
    eng.cfg = cfg
    eng.store = None
    eng.prev = None
    eng.anchor = None
    eng.link_gap = False
    eng._baseline_saved_at = None
    eng._arp_log_read_at = None
    eng.prev_wall = None
    eng.state = {}
    eng.investigator = investigate.Investigator(cfg.data.get("investigate"))
    eng.needs = {}

    out = []
    for obs in observations:
        try:
            wall = datetime.datetime.strptime(obs.ts, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=datetime.timezone.utc).timestamp()
        except ValueError:
            wall = (eng.prev_wall or 0) + cfg.interval
        elapsed = (wall - eng.prev_wall) if eng.prev_wall else 0.0
        findings = eng.judge(obs, elapsed)
        if is_complete(obs):
            eng.prev = obs
        eng.prev_wall = wall
        out.append((obs, findings))
    return out
