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
    iface: str = "en0",
    iface_kind: str = "wifi",
    icmp_ok: Optional[bool] = True,
    rtt: Optional[float] = 3.0,
    arp_replies: int = 1000,
    duplicate_ip: int = 0,
    lease_start: str = "2026-01-01 00:00:00",
    default6=(),
    ipv6_routers=(),
    resolvers=(DNS1,),
    via_loopback: bool = False,
    proxy: Optional[Dict[str, str]] = None,
    shared_macs: Optional[Dict[str, Any]] = None,
    link_active: str = "TRUE",
    vpn: Optional[Dict[str, Any]] = None,
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
    }
    o.data["dhcp"] = {
        "available": True,
        "server_identifier": ident("ipv4", dhcp_server) if dhcp_server else None,
        "routers": [ident("ipv4", r) for r in routers],
        "dns_offered": [ident("ipv4", d) for d in dns],
        "subnet_mask": subnet,
        "yiaddr": ident("ipv4", my_ip) if my_ip else None,
        "lease_start": lease_start,
    }
    o.data["route"] = {
        "default4": [{"gateway": ident("ipv4", gateway), "iface": iface, "flags": "UGScg"}],
        "default6": [{"gateway": ident("ipv6", g), "iface": i, "flags": "UGc"}
                     for g, i in default6],
        "default4_count": 1,
        "default6_count": len(default6),
        "ipv6_routers": [{"addr": ident("ipv6", a), "if": i, "pref": "medium"}
                         for a, i in ipv6_routers],
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


def vpn_state(state="connected", reason=None, provider="warp"):
    return {provider: {"provider": provider, "state": state,
                       "reason": reason, "iface": None}}


def kinds(findings):
    return [f.kind for f in findings]


def by_kind(findings, kind):
    for f in findings:
        if f.kind == kind:
            return f
    return None
