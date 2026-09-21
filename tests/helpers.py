"""합성 관측 만들기.

여기 들어가는 값은 전부 문서용 대역이다. 실제 환경에서 뜬 값을 테스트에
붙여 넣지 않는다 — 저장소는 공개될 수 있다.

  IPv4 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
  IPv6 2001:db8::/32
  MAC  00:00:5e:00:53:xx
  SSID ExampleNet
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from netmon.model import Observation, ident

GW = "192.0.2.1"
GW_MAC = "00:00:5e:00:53:01"
GW_MAC_ALT = "00:00:5e:00:53:02"
MY_IP = "192.0.2.50"
DHCP_SRV = "192.0.2.1"
DNS1 = "192.0.2.53"
DNS2 = "198.51.100.53"
SSID = "ExampleNet"
BSSID = "00:00:5e:00:53:aa"
BSSID_ALT = "00:00:5e:00:53:bb"

# 두 번째 네트워크 (장소 이동 재현용)
GW2 = "198.51.100.1"
GW2_MAC = "00:00:5e:00:53:10"
DHCP_SRV2 = "198.51.100.1"


def obs(
    ts: str = "2026-01-01T00:00:00Z",
    gateway: str = GW,
    gw_mac: Optional[str] = GW_MAC,
    dhcp_server: str = DHCP_SRV,
    subnet: str = "255.255.255.0",
    dns=(DNS1,),
    routers=(GW,),
    my_ip: str = MY_IP,
    ssid: Optional[str] = None,
    bssid: Optional[str] = None,
    security: Optional[str] = "WPA2",
    band=None,
    channel=None,
    txrate=None,
    iface: str = "en0",
    iface_kind: str = "wifi",
    icmp_ok: Optional[bool] = True,
    rtt: Optional[float] = 3.0,
    arp_replies: int = 1000,
    duplicate_ip: int = 0,
    arp_log=None,
    arp_log_enabled: bool = False,
    lease_start: str = "2026-01-01 00:00:00",
    default6=(),
    ipv6_routers=(),
    resolvers=(DNS1,),
    via_loopback: bool = False,
    proxy: Optional[Dict[str, str]] = None,
    shared_macs: Optional[Dict[str, Any]] = None,
    link_active: str = "TRUE",
    vpn: Optional[Dict[str, Any]] = None,
    static_routes: Optional[Dict[str, Any]] = None,
    tunnel_default=(),
    route_counts=None,
    offered_egress=(),
) -> Observation:
    o = Observation(ts=ts)
    o.data["iface"] = {
        "primary": iface,
        "primary_kind": iface_kind,
        "primary_status": "active",
        "default4_iface": iface,
        "default4_gateway": ident("ipv4", gateway) if gateway else None,
        "scoped_gateway": ident("ipv4", gateway) if gateway else None,
        "tunnel_iface": None,
    }
    o.data["arp"] = {
        "neighbors": 4,
        "gateway_mac": ident("mac", gw_mac) if gw_mac else None,
        "duplicate_ip_seen": duplicate_ip,
        "replies_received": arp_replies,
        "requests_received": arp_replies * 3,
        "shared_macs": shared_macs or {},
        "log_enabled": arp_log_enabled,
        **({"log_events": list(arp_log)} if arp_log else {}),
    }
    o.data["dhcp"] = {
        "available": True,
        "server_identifier": ident("ipv4", dhcp_server) if dhcp_server else None,
        "routers": [ident("ipv4", r) for r in routers],
        "dns_offered": [ident("ipv4", d) for d in dns],
        "subnet_mask": subnet,
        "yiaddr": ident("ipv4", my_ip) if my_ip else None,
        "lease_start": lease_start,
        "static_routes": static_routes or {"present": False, "option": None,
                                           "parsed": True, "routes": []},
    }
    o.data["route"] = {
        "default4": [{"gateway": ident("ipv4", gateway), "iface": iface, "flags": "UGScg"}],
        "default6": [{"gateway": ident("ipv6", g), "iface": i, "flags": "UGc"}
                     for g, i in default6],
        "default4_count": 1,
        "default6_count": len(default6),
        "ipv6_routers": [{"addr": ident("ipv6", a), "if": i, "pref": "medium"}
                         for a, i in ipv6_routers],
        "tunnel_default": list(tunnel_default),
        "route_counts": dict(route_counts or {}),
        "offered_egress": [{"dest": ident("ipv4", d), "iface": i,
                            "matched_default": False}
                           for d, i in offered_egress],
    }
    o.data["dns"] = {
        "resolvers": [ident("ipv4", r) for r in resolvers],
        "resolver_count": len(resolvers),
        "via_loopback": via_loopback,
        "proxy": proxy or {},
        "proxy_any": bool(proxy),
    }
    o.data["wifi"] = {
        "applicable": iface_kind == "wifi",
        "security": security,
        "link_active": link_active,
        **({"band": band} if band else {}),
        **({"channel": channel} if channel else {}),
        **({"txrate": txrate} if txrate else {}),
        "location": "granted" if ssid else "denied",
        "ssid": ident("ssid", ssid) if ssid else None,
        "bssid": ident("bssid", bssid) if bssid else None,
    }
    o.data["link"] = {
        "targets": {"gateway": ident("ipv4", gateway)} if gateway else {},
        "results": {"gateway": {"reachable": icmp_ok, "rtt_ms": rtt}},
        "gateway_reachable": icmp_ok,
        "gateway_rtt_ms": rtt if icmp_ok else None,
    }
    if vpn is not None:
        o.data["vpn"] = vpn
    return o


def command_failed(o, error="timed out"):
    """ping 명령 자체가 실행되지 못한 평소(single) 주기.

    `collect/link.collect` 의 예외 처리가 남기는 모양 그대로다 — 결과에는
    `reachable` False 와 **단수 키** `error` 뿐이고, 받은 수도 손실률도
    없다. 이 `reachable` 은 "무응답" 이 아니라 "재지 못함" 이다.

    끊김 요약문(tests/test_detect_vpn)과 조사 결론(tests/test_investigate)이
    같은 주기를 같은 모양으로 보게 하려고 여기 둔다.
    """
    o.data["link"]["results"]["gateway"] = {"reachable": False, "error": error}
    o.data["link"]["gateway_reachable"] = False
    o.data["link"]["gateway_rtt_ms"] = None
    o.data["link"]["first_hop_probes"] = 1
    return o


# 터널 엔드포인트. 문서용 대역이다 — 실제 공급자가 준 주소를 적지 않는다.
ENDPOINT = "198.51.100.7"
ENDPOINT_REASON = "No Network via 198.51.100.7:2408"


def endpoint_probe(o, addr=ENDPOINT, reachable=True, rtt=25.0, error=None):
    """터널 엔드포인트를 잰 주기의 link 관측.

    `collect/link.collect` 가 만드는 모양 그대로다 — `targets` 에는 **감싼**
    주소가, `results` 에는 ping 결과(또는 실행 실패 표시)가 들어간다.
    실행 실패의 `error` 는 예외 종류 이름까지다(`collect/link._error_note`).

    실제 수집기로 만든 관측과 같은 모양인지는 `tests/test_link.py` 와
    `tests/test_detect_vpn.py` 의 수집기 연결 시험이 함께 본다.
    """
    o.data["link"].setdefault("targets", {})["tunnel_endpoint"] = ident("ipv4", addr)
    if error:
        got = {"reachable": False, "error": error}
    else:
        got = {"rtt_ms": rtt if reachable else None,
               "rtt_max_ms": rtt if reachable else None,
               "loss_pct": 0.0 if reachable else 100.0,
               "replies": 1 if reachable else 0,
               "reachable": bool(reachable)}
    o.data["link"].setdefault("results", {})["tunnel_endpoint"] = got
    return o


def vpn_state(state="connected", reason=None, provider="warp",
              mode=None, tunnel=None):
    return {provider: {"provider": provider, "state": state,
                       "reason": reason, "iface": None,
                       "mode": mode, "tunnel": tunnel}}


def kinds(findings):
    return [f.kind for f in findings]


def by_kind(findings, kind):
    for f in findings:
        if f.kind == kind:
            return f
    return None
