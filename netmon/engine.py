"""수집 → 판정 → 저장을 잇는 한 주기.

수집기 실행 순서에 의존이 있다. iface 가 주 인터페이스와 게이트웨이를
정해야 나머지가 무엇을 볼지 알고, dns 가 리졸버를 알려줘야 link 가
측정 대상을 정한다.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple

from . import baseline, investigate, messages, vpn
from .collect import arp, dhcp, dns, iface, link, route, wifi
from .config import Config
from .detect import (Context, attributions_for, is_complete, network_key,
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


class Engine:
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
        self.investigator = investigate.Investigator(cfg.data.get("investigate"))
        # 조사가 요청한 측정 변화. 다음 주기에 반영된다.
        self.needs: Dict[str, Any] = {}

    # --- 수집 ---
    def observe(self) -> Observation:
        obs = Observation(ts=ts_now())
        ctx: Dict[str, Any] = {
            "allow_location": self.cfg.effective("detect.evil_twin"),
            "allow_external": self.cfg.effective("detect.public_ip"),
            "config_home": os.path.dirname(self.cfg.path),
            "wifi_helper_interval": self.cfg.data.get("wifi_helper_interval", 15),
            "ping_count": self.cfg.data.get("ping_count", 1),
        }

        def step(module, name: str) -> None:
            try:
                obs.data[name] = module.collect(ctx)
            except Exception as exc:
                obs.errors[name] = "%s: %s" % (type(exc).__name__, str(exc)[:120])
                obs.data[name] = {}

        step(iface, "iface")
        ctx["primary"] = obs.data["iface"].get("primary")
        ctx["primary_kind"] = obs.data["iface"].get("primary_kind")
        gw = unwrap(obs.data["iface"].get("default4_gateway")) or \
            unwrap(obs.data["iface"].get("scoped_gateway"))
        ctx["gateway"] = gw

        step(arp, "arp")
        step(dhcp, "dhcp")
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
                obs.errors["vpn"] = str(exc)[:120]

        return obs

    def _wifi_changed_hint(self, obs: Observation) -> bool:
        if self.prev is None:
            return True
        for block, key in (("arp", "gateway_mac"), ("dhcp", "server_identifier"),
                           ("dhcp", "lease_start")):
            if unwrap(self.prev.get(block, key)) != unwrap(obs.get(block, key)):
                return True
        return False

    # --- 판정 ---
    def judge(self, obs: Observation, elapsed: float) -> List[Finding]:
        interval = float(self.cfg.interval)

        # 주 인터페이스가 없으면 비교할 상태가 아니다. 기록만 남기고 넘어간다.
        # 기준선도 건드리지 않는다 — 링크가 없는 동안의 값은 기준이 될 수 없다.
        if not is_complete(obs):
            self.link_gap = True
            return [Finding(axis=INFO, kind="LINK_ABSENT", confidence=CONFIRMED,
                            severity=INFO_SEV, summary=msg.LINK_ABSENT,
                            evidence={"iface": obs.get("iface") or {}},
                            network=self.state.get("network"))]

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
            features={k: self.cfg.effective(k) for k in self.cfg.data.get("features", {})
                      if k.startswith("detect.")},
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
