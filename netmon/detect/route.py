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

    # --- 터널 밖 인터페이스에 경로가 새로 생김 ---
    # 터널 기본 경로가 있는데 물리 인터페이스 쪽 경로가 늘면, 그만큼의 대역이
    # 터널에서 빠져나간 것이다. 기본 경로만 봐서는 보이지 않는 모양이다.
    tun = cur.get("route", "tunnel_default") or []
    p_counts = prev.get("route", "route_counts") or {}
    c_counts = cur.get("route", "route_counts") or {}
    if tun and c_counts and p_counts:
        grew = {i: (p_counts.get(i, 0), n) for i, n in c_counts.items()
                if i not in tun and n > p_counts.get(i, 0)}
        if grew:
            attribution = ctx.identity_attribution() or (
                "vpn_change" if ctx.has("vpn_change") else None)
            added = sum(n - p for p, n in grew.values())
            out.append(Finding(
                axis=SECURITY, kind="ROUTES_OUTSIDE_TUNNEL",
                confidence=CONFIRMED,
                severity=LOW if attribution else MEDIUM,
                summary=msg.ROUTES_OUTSIDE_TUNNEL % (added, ", ".join(sorted(grew))),
                evidence={"grew": {i: {"prev": p, "cur": n} for i, (p, n) in grew.items()},
                          "tunnel_default": tun, "source": "netstat -rn -f inet"},
                attribution=attribution,
            ))

    # --- DHCP 가 밀어 넣은 정적 경로 (CVE-2024-3661 벡터) ---
    p_sr = prev.get("dhcp", "static_routes") or {}
    c_sr = cur.get("dhcp", "static_routes") or {}
    if c_sr.get("present") and not p_sr.get("present"):
        attribution = ctx.identity_attribution()
        parsed = c_sr.get("parsed", True)
        routes = c_sr.get("routes") or []
        out.append(Finding(
            axis=SECURITY, kind="DHCP_STATIC_ROUTES",
            confidence=CONFIRMED,
            severity=LOW if attribution else MEDIUM,
            summary=(msg.DHCP_STATIC_ROUTES % len(routes) if parsed
                     else msg.DHCP_STATIC_ROUTES_UNREAD),
            evidence={"option": c_sr.get("option"), "parsed": parsed,
                      "routes": routes, "source": "ipconfig getpacket"},
            attribution=attribution,
        ))

    # --- 제공된 경로가 터널 밖으로 나간다 ---
    # 기본 경로만 봐서는 보이지 않는다. 터널 기본 경로가 있는데 DHCP 가 준
    # 대역이 터널이 아닌 인터페이스로 나가면, 그 대역은 보호 밖이다.
    tunnels = cur.get("route", "tunnel_default") or []
    if tunnels:
        # **매칭된 경로가 기본 경로면 세지 않는다.** 제공된 대역이 설치되지
        # 않아 조회가 기본 경로로 떨어진 것일 수 있고, 그때 기본 경로가 물리
        # 인터페이스면 없는 우회를 만들어 낸다. 실제로 설치되어 매칭된
        # 경우만 사실로 말한다. (0.0.0.0/0 제공 자체는 DHCP_STATIC_ROUTES 가 알림)
        outside = [e for e in (cur.get("route", "offered_egress") or [])
                   if e.get("iface") and e["iface"] not in tunnels
                   and not e.get("matched_default")]
        prev_outside = {unwrap(e.get("dest")) for e in (prev.get("route", "offered_egress") or [])
                        if e.get("iface") and e["iface"] not in (prev.get("route", "tunnel_default") or [])
                        and not e.get("matched_default")}
        fresh = [e for e in outside if unwrap(e.get("dest")) not in prev_outside]
        if fresh:
            out.append(Finding(
                axis=SECURITY, kind="TUNNEL_BYPASS_ROUTE",
                confidence=CONFIRMED, severity=HIGH,
                summary=msg.TUNNEL_BYPASS_ROUTE % len(fresh),
                evidence={"routes": fresh, "tunnel_default": tunnels,
                          "source": "route -n get"},
                # 이동으로 설명되지 않는다. 새 네트워크라도 DHCP 가 준 대역이
                # 터널 밖으로 나가는 것은 그 자체로 봐야 할 사실이다.
                attribution=None,
            ))

    return out
