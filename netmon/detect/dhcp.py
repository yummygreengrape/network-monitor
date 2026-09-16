"""DHCP 판정 — rogue DHCP 서버, 라우터·DNS 옵션 변조."""
from __future__ import annotations

from typing import Any, List, Optional

from .. import messages as msg
from ..model import (CONFIRMED, HIGH, INFO, LOW, MEDIUM, QUALITY, SECURITY,
                     Finding, Observation, unwrap)

FEATURE = "detect.dhcp"


def _vals(obs: Optional[Observation], key: str) -> List[str]:
    if obs is None:
        return []
    raw = obs.get("dhcp", key) or []
    if isinstance(raw, dict):
        raw = [raw]
    return [str(unwrap(v)) for v in raw]


def detect(prev: Optional[Observation], cur: Observation, ctx) -> List[Finding]:
    out: List[Finding] = []
    if prev is None or not cur.get("dhcp", "available"):
        return out

    attribution = ctx.identity_attribution()

    # --- DHCP 서버가 바뀜 ---
    p_srv = unwrap(prev.get("dhcp", "server_identifier"))
    c_srv = unwrap(cur.get("dhcp", "server_identifier"))
    if p_srv and c_srv and p_srv != c_srv:
        out.append(Finding(
            axis=SECURITY, kind="DHCP_SERVER_CHANGED",
            confidence=CONFIRMED,
            severity=LOW if attribution else HIGH,
            summary=(msg.DHCP_SERVER_CHANGED_MOVED if attribution else msg.DHCP_SERVER_CHANGED),
            evidence={"prev": prev.get("dhcp", "server_identifier"),
                      "cur": cur.get("dhcp", "server_identifier"),
                      "source": "ipconfig getpacket"},
            attribution=attribution,
        ))

    # --- 라우터 옵션이 바뀜 ---
    p_r, c_r = _vals(prev, "routers"), _vals(cur, "routers")
    if p_r and c_r and p_r != c_r:
        out.append(Finding(
            axis=SECURITY, kind="DHCP_ROUTER_CHANGED",
            confidence=CONFIRMED,
            severity=LOW if attribution else HIGH,
            summary=msg.DHCP_ROUTER_CHANGED,
            evidence={"prev": prev.get("dhcp", "routers"), "cur": cur.get("dhcp", "routers"),
                      "source": "ipconfig getpacket"},
            attribution=attribution,
        ))

    # --- DNS 옵션이 바뀜 ---
    p_d, c_d = _vals(prev, "dns_offered"), _vals(cur, "dns_offered")
    if p_d and c_d and p_d != c_d:
        out.append(Finding(
            axis=SECURITY, kind="DHCP_DNS_CHANGED",
            confidence=CONFIRMED,
            severity=LOW if attribution else HIGH,
            summary=msg.DHCP_DNS_CHANGED,
            evidence={"prev": prev.get("dhcp", "dns_offered"), "cur": cur.get("dhcp", "dns_offered"),
                      "source": "ipconfig getpacket"},
            attribution=attribution,
        ))

    # --- 임대 갱신 ---
    # 보안 사건이 아니라 "재접속이 있었다"는 품질 신호다.
    p_l = prev.get("dhcp", "lease_start")
    c_l = cur.get("dhcp", "lease_start")
    if p_l and c_l and p_l != c_l:
        out.append(Finding(
            axis=QUALITY, kind="DHCP_LEASE_RENEWED",
            confidence=CONFIRMED, severity="info",
            summary=msg.DHCP_LEASE_RENEWED,
            evidence={"prev": p_l, "cur": c_l, "source": "ipconfig getsummary"},
            attribution=ctx.quality_attribution(),
        ))

    # --- 내 IP 가 바뀜 ---
    p_ip = unwrap(prev.get("dhcp", "yiaddr"))
    c_ip = unwrap(cur.get("dhcp", "yiaddr"))
    if p_ip and c_ip and p_ip != c_ip:
        out.append(Finding(
            axis=INFO, kind="OWN_IP_CHANGED",
            confidence=CONFIRMED, severity="info",
            summary=msg.OWN_IP_CHANGED,
            evidence={"prev": prev.get("dhcp", "yiaddr"), "cur": cur.get("dhcp", "yiaddr"),
                      "source": "ipconfig getpacket"},
            attribution=ctx.quality_attribution(),
        ))

    return out
