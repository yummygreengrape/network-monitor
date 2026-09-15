"""수집 → 판정 → 저장을 잇는 한 주기.

수집기 실행 순서에 의존이 있다. iface 가 주 인터페이스와 게이트웨이를
정해야 나머지가 무엇을 볼지 알고, dns 가 리졸버를 알려줘야 link 가
측정 대상을 정한다.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from . import baseline, vpn
from .collect import arp, dhcp, dns, iface, link, route, wifi
from .config import Config
from .detect import Context, attributions_for, network_key, run_all
from .model import Finding, Observation, unwrap
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
        self.prev: Optional[Observation] = None
        self.prev_wall: Optional[float] = None
        self.state: Dict[str, Any] = store.load_state()

    # --- 수집 ---
    def observe(self) -> Observation:
        obs = Observation(ts=ts_now())
        ctx: Dict[str, Any] = {
            "allow_location": self.cfg.effective("detect.evil_twin"),
            "allow_external": self.cfg.effective("detect.public_ip"),
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

    # --- 판정 ---
    def judge(self, obs: Observation, elapsed: float) -> List[Finding]:
        interval = float(self.cfg.interval)
        attributions = attributions_for(self.prev, obs, elapsed, interval)
        changed = "network_change" in attributions or "iface_change" in attributions
        if changed:
            self.state = baseline.reset_for_new_network(self.state)

        self.state = baseline.update_counters(self.state, obs)

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
        self.state = baseline.update_baselines(self.state, obs)
        self.state["network"] = ctx.network
        self.state["last_ts"] = obs.ts
        return findings

    # --- 한 주기 ---
    def cycle(self, now: Optional[float] = None) -> Tuple[Observation, List[Finding]]:
        import time
        now = now if now is not None else time.time()
        elapsed = (now - self.prev_wall) if self.prev_wall else 0.0
        obs = self.observe()
        findings = self.judge(obs, elapsed)
        self.prev, self.prev_wall = obs, now
        return obs, findings

    def persist(self, obs: Observation, findings: List[Finding]) -> None:
        self.store.write_sample(obs)
        self.store.write_findings(obs.ts, findings)
        self.store.save_state(self.state)


def replay(cfg: Config, observations: List[Observation]) -> List[Tuple[Observation, List[Finding]]]:
    """캡처한 관측 열을 그대로 다시 판정한다. 네트워크가 필요 없다.

    현장에서 뜬 오탐을 집에서 재현하고, 고친 뒤 회귀로 남기는 데 쓴다.
    """
    import datetime

    eng = Engine.__new__(Engine)
    eng.cfg = cfg
    eng.store = None
    eng.prev = None
    eng.prev_wall = None
    eng.state = {}

    out = []
    for obs in observations:
        try:
            wall = datetime.datetime.strptime(obs.ts, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=datetime.timezone.utc).timestamp()
        except ValueError:
            wall = (eng.prev_wall or 0) + cfg.interval
        elapsed = (wall - eng.prev_wall) if eng.prev_wall else 0.0
        findings = eng.judge(obs, elapsed)
        eng.prev, eng.prev_wall = obs, wall
        out.append((obs, findings))
    return out
