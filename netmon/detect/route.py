"""경로 판정 — 기본 경로 변경, IPv6 RA 로 생긴 경로.

IPv4 만 보면 통째로 놓치는 것이 있다. 같은 L2 의 누구나 IPv6 라우터 광고를
쏘아 기본 경로를 만들 수 있고, IPv4 설정을 전혀 건드리지 않고도 트래픽을
가져갈 수 있다. macOS 는 IPv6 를 기본으로 선호한다.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from .. import messages as msg
from ..model import (CONFIRMED, HIGH, INFO, LOW, MEDIUM, SECURITY, SUSPECT,
                     Finding, Observation, unwrap)

FEATURE = "detect.route"


def _routes(obs: Optional[Observation], key: str) -> Set[str]:
    if obs is None:
        return set()
    out = set()
    for r in obs.get("route", key) or []:
        out.add("%s@%s" % (unwrap(r.get("gateway")), r.get("iface")))
    return out


TUNNEL_PREFIXES = ("utun", "ipsec", "ppp", "tun", "tap")


def _is_tunnel_route(route_key: str) -> bool:
    """"<게이트웨이>@<인터페이스>" 형태에서 인터페이스가 터널인가."""
    iface = route_key.rsplit("@", 1)[-1]
    return iface.startswith(TUNNEL_PREFIXES)


def _router_addrs(obs: Optional[Observation]) -> Set[str]:
    if obs is None:
        return set()
    return {str(unwrap(r.get("addr"))) for r in (obs.get("route", "ipv6_routers") or [])}


def detect(prev: Optional[Observation], cur: Observation, ctx) -> List[Finding]:
    out: List[Finding] = []
    if prev is None:
        return out

    attribution = ctx.identity_attribution()

    # --- IPv4 기본 경로 ---
    p4, c4 = _routes(prev, "default4"), _routes(cur, "default4")
    route_attribution = attribution
    if route_attribution is None and (ctx.has("vpn_change") or ctx.settling):
        changed = (p4 ^ c4)
        p_phys = {r for r in p4 if not _is_tunnel_route(r)}
        c_phys = {r for r in c4 if not _is_tunnel_route(r)}
        # 1) 터널 경로만 달라짐 → VPN 이 오르내린 결과
        if changed and all(_is_tunnel_route(r) for r in changed):
            route_attribution = "vpn_change" if ctx.has("vpn_change") else ctx.settling
        # 2) 물리 경로가 **없다가 생김** → 링크가 돌아온 결과.
        #    있던 물리 경로가 **다른 게이트웨이로 바뀐 것**은 설명되지 않는다 —
        #    그것이 경로를 가로채는 모양이다.
        elif not p_phys and c_phys:
            route_attribution = ctx.settling or "vpn_change"
    if p4 and c4 and p4 != c4:
        out.append(Finding(
            axis=SECURITY, kind="DEFAULT_ROUTE_CHANGED",
            confidence=CONFIRMED,
            severity=LOW if route_attribution else HIGH,
            summary=msg.DEFAULT_ROUTE_CHANGED,
            evidence={"prev": sorted(p4), "cur": sorted(c4), "source": "netstat -rn -f inet"},
            attribution=route_attribution,
        ))

    # --- IPv6 기본 경로가 새로 생김 ---
    p6, c6 = _routes(prev, "default6"), _routes(cur, "default6")
    appeared = c6 - p6
    if appeared:
        # 터널 인터페이스를 통한 것은 VPN 이 켜진 결과다. 물리 인터페이스에
        # 생긴 것만 RA 주입 후보로 본다.
        physical = [r for r in appeared if "@utun" not in r and "@ipsec" not in r and "@ppp" not in r]
        if physical:
            out.append(Finding(
                axis=SECURITY, kind="IPV6_DEFAULT_ROUTE_APPEARED",
                confidence=CONFIRMED,
                severity=MEDIUM if attribution else HIGH,
                summary=msg.IPV6_DEFAULT_ROUTE_APPEARED,
                evidence={"appeared": sorted(physical), "prev": sorted(p6),
                          "source": "netstat -rn -f inet6"},
                attribution=attribution,
            ))

    # --- IPv6 라우터 목록 변화 ---
    p_r, c_r = _router_addrs(prev), _router_addrs(cur)
    new_routers = c_r - p_r
    if new_routers and p_r:
        out.append(Finding(
            axis=SECURITY, kind="IPV6_ROUTER_APPEARED",
            confidence=SUSPECT,
            severity=LOW if attribution else MEDIUM,
            summary=msg.IPV6_ROUTER_APPEARED % len(new_routers),
            evidence={"new": [{"id": "ipv6", "v": a} for a in sorted(new_routers)],
                      "source": "ndp -rn"},
            attribution=attribution,
        ))

    # --- 기본 경로가 여러 개 ---
    n4 = cur.get("route", "default4_count") or 0
    if n4 > 1 and (prev.get("route", "default4_count") or 0) <= 1:
        out.append(Finding(
            axis=INFO, kind="MULTIPLE_DEFAULT_ROUTES",
            confidence=CONFIRMED, severity="info",
            summary=msg.MULTIPLE_DEFAULT_ROUTES % n4,
            evidence={"routes": sorted(c4), "source": "netstat -rn -f inet"},
        ))

    return out
