"""링크 계층 판정 — 게이트웨이 MAC, IP 충돌, ARP 이상.

이 네트워크에서 현실적으로 가장 자주 가능한 공격이 여기 있다. 같은 PSK 를
아는 사람은 누구나 ARP 를 위조할 수 있고, 특별한 장비가 필요 없다.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..model import CONFIRMED, HIGH, LOW, MEDIUM, POSSIBLE, SECURITY, SUSPECT, Finding, Observation, unwrap

FEATURE = "detect.l2"

# ARP 응답 수신량이 이 배수 이상으로 뛰면 이상으로 본다. 정상 변동과
# 구분하려고 절대 하한도 같이 둔다.
REPLY_SPIKE_FACTOR = 8.0
REPLY_SPIKE_MIN = 60


def _gw_mac(obs: Observation) -> Optional[str]:
    return unwrap(obs.get("arp", "gateway_mac"))


def detect(prev: Optional[Observation], cur: Observation, ctx) -> List[Finding]:
    out: List[Finding] = []
    if prev is None:
        return out

    prev_mac, cur_mac = _gw_mac(prev), _gw_mac(cur)
    gw = unwrap(cur.get("iface", "default4_gateway"))

    # --- 게이트웨이 MAC 변경 ---
    # 관측 자체는 확정이다. 원인(스푸핑/AP 교체/로밍)은 여기서 단정하지 않는다.
    if prev_mac and cur_mac and prev_mac != cur_mac:
        attribution = ctx.identity_attribution()
        out.append(Finding(
            axis=SECURITY, kind="GW_MAC_CHANGED",
            confidence=CONFIRMED,
            severity=LOW if attribution else HIGH,
            summary=(
                "게이트웨이 MAC 이 바뀌었습니다. 같은 네트워크에 머물러 있는데 바뀐 것이라 "
                "ARP 스푸핑이나 접속점 교체를 의심할 수 있습니다."
                if not attribution else
                "게이트웨이 MAC 이 바뀌었지만, 같은 시점에 네트워크도 달라졌습니다."
            ),
            evidence={
                "gateway": cur.get("iface", "default4_gateway"),
                "prev_mac": prev.get("arp", "gateway_mac"),
                "mac": cur.get("arp", "gateway_mac"),
                "source": "arp -an -x",
            },
            attribution=attribution,
        ))

    # --- IP 충돌 ---
    p_dup = prev.get("arp", "duplicate_ip_seen")
    c_dup = cur.get("arp", "duplicate_ip_seen")
    if isinstance(p_dup, int) and isinstance(c_dup, int) and c_dup > p_dup:
        out.append(Finding(
            axis=SECURITY, kind="DUPLICATE_IP",
            confidence=CONFIRMED, severity=MEDIUM,
            summary="IP 충돌이 감지됐습니다 (Duplicate IP seen 카운터가 %d회 늘었습니다)." % (c_dup - p_dup),
            evidence={"prev": p_dup, "cur": c_dup, "source": "netstat -s -p arp"},
        ))

    # --- ARP 응답 폭주 ---
    p_rep = prev.get("arp", "replies_received")
    c_rep = cur.get("arp", "replies_received")
    if isinstance(p_rep, int) and isinstance(c_rep, int) and c_rep >= p_rep:
        delta = c_rep - p_rep
        base = ctx.state.get("arp_reply_rate")
        if base and delta > max(REPLY_SPIKE_MIN, base * REPLY_SPIKE_FACTOR):
            out.append(Finding(
                axis=SECURITY, kind="ARP_REPLY_SPIKE",
                confidence=SUSPECT, severity=MEDIUM,
                summary="ARP 응답 수신량이 평소의 %.0f배로 늘었습니다 (%d건/주기, 기준 %.1f)."
                        % (delta / base, delta, base),
                evidence={"delta": delta, "baseline": round(base, 2),
                          "source": "netstat -s -p arp"},
                attribution=ctx.quality_attribution() if ctx.moved else None,
            ))

    # --- 한 MAC 이 여러 IP 를 쥐고 있음 ---
    # 라우터가 대리 응답하는 정상 구성에서도 나온다. 그래서 '가능'에 머문다.
    prev_shared = set((prev.get("arp", "shared_macs") or {}).keys())
    cur_shared = cur.get("arp", "shared_macs") or {}
    new_shared = {m: v for m, v in cur_shared.items() if m not in prev_shared}
    for mac, ips in new_shared.items():
        if len(ips) < 3:
            continue
        out.append(Finding(
            axis=SECURITY, kind="SHARED_MAC",
            confidence=POSSIBLE, severity=LOW,
            summary="한 MAC 이 IP %d개를 동시에 쓰고 있습니다. ARP 스푸핑에서 나타나는 형태이지만 "
                    "라우터가 대리 응답하는 정상 구성에서도 같은 형태가 나옵니다." % len(ips),
            evidence={"mac": {"id": "mac", "v": mac}, "addresses": ips[:8],
                      "source": "arp -an -x"},
        ))

    return out
