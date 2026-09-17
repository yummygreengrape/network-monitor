"""기본 경로와 IPv6 라우터 광고.

IPv4 만 보면 통째로 놓치는 것이 있다. 같은 L2 에 있는 누구나 IPv6 RA 를
쏘아 기본 경로를 만들 수 있고, 그러면 IPv4 설정을 건드리지 않고도
트래픽을 가져갈 수 있다.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..model import ident, unwrap
from .iface import is_tunnel
from ..util import OK, Capability, run

NAME = "route"


def parse_netstat_routes(text: str, family: str = "inet") -> List[Dict[str, str]]:
    """`netstat -rn -f <family>` 에서 기본 경로 줄만 뽑는다."""
    out: List[Dict[str, str]] = []
    for raw in text.splitlines():
        parts = raw.split()
        if len(parts) < 4:
            continue
        if parts[0] not in ("default", "::/0"):
            continue
        dest, gw, flags = parts[0], parts[1], parts[2]
        netif = parts[3] if len(parts) > 3 else ""
        # 열 수가 버전에 따라 다르다. Netif 는 flags 다음이지만, 일부
        # 출력에서는 Refs/Use 가 끼어든다. 인터페이스처럼 생긴 토큰을 찾는다.
        if not any(netif.startswith(p) for p in ("en", "utun", "ipsec", "ppp", "bridge", "lo", "awdl", "tun")):
            for tok in parts[3:]:
                if any(tok.startswith(p) for p in ("en", "utun", "ipsec", "ppp", "bridge", "lo", "tun")):
                    netif = tok
                    break
        out.append({"dest": dest, "gateway": gw, "flags": flags, "iface": netif, "family": family})
    return out


def parse_ndp_routers(text: str) -> List[Dict[str, str]]:
    """`ndp -rn` 의 IPv6 라우터 목록."""
    out: List[Dict[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or "if=" not in line:
            continue
        addr = line.split()[0].split("%", 1)[0]
        fields = {"addr": addr}
        for part in line.split(","):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                fields[k.split()[-1].strip()] = v.strip()
        out.append(fields)
    return out


def probe() -> Capability:
    r = run(["netstat", "-rn", "-f", "inet"], timeout=6)
    status = OK if r.rc == 0 else "broken"
    return Capability(NAME, status, "경로 표 조회 가능" if r.rc == 0 else "netstat 실패",
                      provides=["default_routes", "ipv6_routers"])


def parse_route_get_match(text: str) -> Dict[str, Optional[str]]:
    """실제 송신 인터페이스와 **어떤 경로에 매칭됐는지**.

    매칭된 경로를 함께 봐야 한다. 제공된 대역이 설치되지 않았으면 조회가
    기본 경로로 떨어지는데, 기본 경로가 물리 인터페이스면 "터널 밖"으로
    잘못 읽힌다 — 이 기기에서 실제로 그렇게 나왔다.
    """
    out: Dict[str, Optional[str]] = {"iface": None, "destination": None}
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("interface:"):
            out["iface"] = line.split(":", 1)[1].strip() or None
        elif line.startswith("destination:"):
            out["destination"] = line.split(":", 1)[1].strip() or None
    return out


def egress_for(dests: List[str]) -> List[Dict[str, Any]]:
    """각 목적지가 실제로 어느 인터페이스로 나가는지 조회한다.

    **기본 경로만 봐서는 알 수 없다.** 더 구체적인 경로가 깔리면 기본 경로는
    그대로인 채 트래픽만 다른 곳으로 간다 — 이 기기에서 VPN 이 그렇게 동작하는
    것을 확인했고, CVE-2024-3661 이 같은 메커니즘을 공격에 쓴다.
    """
    out: List[Dict[str, Any]] = []
    for dest in dests[:16]:          # rogue 가 목록을 부풀려 주기를 늘리지 못하게 상한
        probe = dest.split("/", 1)[0]
        r = run(["route", "-n", "get", probe], timeout=4)
        m = parse_route_get_match(r.out) if r.rc == 0 else {"iface": None, "destination": None}
        out.append({"dest": ident("ipv4", dest), "iface": m["iface"],
                    "matched_default": m["destination"] == "default"})
    return out


def collect(ctx: Dict[str, Any] = None) -> Dict[str, Any]:
    v4 = parse_netstat_routes(run(["netstat", "-rn", "-f", "inet"], timeout=8).out, "inet")
    v6 = parse_netstat_routes(run(["netstat", "-rn", "-f", "inet6"], timeout=10).out, "inet6")
    routers = parse_ndp_routers(run(["ndp", "-rn"], timeout=6).out)

    def norm(rows: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        out = []
        for r in rows:
            gw = r["gateway"]
            # link#N 은 주소가 아니라 인터페이스 직결이다. 식별자가 아니다.
            wrapped = gw if gw.startswith("link#") else ident(
                "ipv6" if ":" in gw else "ipv4", gw)
            out.append({"gateway": wrapped, "iface": r["iface"], "flags": r["flags"]})
        return out

    # 터널로 나가는 기본 경로가 있는가. 있으면 "그보다 구체적인 경로"가
    # 터널 우회를 뜻할 수 있다.
    tunnel_default = [r["iface"] for r in v4 if is_tunnel(r["iface"])]

    # DHCP 가 정적 경로를 제공했을 때만 조회한다. 평소에는 비용이 0 이다.
    offered = [unwrap(r["dest"]) for r in ((ctx or {}).get("dhcp_static_routes") or [])]
    offered_egress = egress_for([d for d in offered if d]) if offered else []

    return {
        "default4": norm(v4),
        "default6": norm(v6),
        "default4_count": len(v4),
        "default6_count": len(v6),
        "tunnel_default": tunnel_default,
        # 제공된 경로가 없으면 키 자체를 넣지 않는다 (평시 비용 0)
        **({"offered_egress": offered_egress} if offered_egress else {}),
        "ipv6_routers": [
            {"addr": ident("ipv6", r["addr"]), "if": r.get("if"), "pref": r.get("pref")}
            for r in routers
        ],
    }
