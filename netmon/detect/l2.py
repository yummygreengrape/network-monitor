"""링크 계층 판정 — 게이트웨이 MAC, IP 충돌, ARP 이상.

이 네트워크에서 현실적으로 가장 자주 가능한 공격이 여기 있다. 같은 PSK 를
아는 사람은 누구나 ARP 를 위조할 수 있고, 특별한 장비가 필요 없다.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .. import messages as msg
from ..collect.arp import SHARED_MAC_MIN_ADDRESSES
from ..model import CONFIRMED, HIGH, LOW, MEDIUM, POSSIBLE, SECURITY, SUSPECT, Finding, Observation, unwrap

FEATURE = "detect.l2"

# ARP 응답 수신이 평소의 이 배수를 넘으면 이상으로 본다. 정상 변동과
# 구분하려고 절대 하한(초당 건수)도 같이 둔다.
#
# **초당 건수로 비교한다.** 누적 카운터의 증가분을 그대로 쓰면 주기 사이가
# 벌어졌을 때 그만큼 커진다 — 잠자기로 939초가 벌어진 구간에서 실제로
# 거짓 경보가 났다. 그때 초당 건수는 평소의 12분의 1이었다.
REPLY_SPIKE_FACTOR = 8.0
REPLY_SPIKE_MIN_RATE = 10.0


def _shared_entry(entry: Any) -> Tuple[int, List[Any]]:
    """shared_macs 의 한 항목을 (개수, 주소 목록)으로.

    옛 기록은 주소 목록만 들고 있었다. 형식이 바뀌어도 그때 뜬 캡처를
    재생할 수 있어야 한다.
    """
    if isinstance(entry, dict):
        addresses = entry.get("addresses") or []
        return int(entry.get("count", len(addresses))), list(addresses)
    if isinstance(entry, list):
        return len(entry), list(entry)
    return 0, []


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
            summary=(msg.GW_MAC_CHANGED_MOVED if attribution else msg.GW_MAC_CHANGED),
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
            summary=msg.DUPLICATE_IP % (c_dup - p_dup),
            evidence={"prev": p_dup, "cur": c_dup, "source": "netstat -s -p arp"},
        ))

    # --- ARP 응답 폭주 ---
    p_rep = prev.get("arp", "replies_received")
    c_rep = cur.get("arp", "replies_received")
    # 측정이 크게 벌어진 주기는 건너뛴다. 그 구간의 카운터 증가분은 무엇을
    # 뜻하는지 알 수 없다 — 자는 동안 인터페이스가 내려갔을 수도 있다.
    if (isinstance(p_rep, int) and isinstance(c_rep, int) and c_rep >= p_rep
            and not ctx.has("sleep")):
        span = float(ctx.elapsed) if ctx.elapsed and ctx.elapsed > 0 else float(ctx.interval)
        rate = (c_rep - p_rep) / span
        base = ctx.state.get("arp_reply_rate")
        if base and rate > max(REPLY_SPIKE_MIN_RATE, base * REPLY_SPIKE_FACTOR):
            out.append(Finding(
                axis=SECURITY, kind="ARP_REPLY_SPIKE",
                confidence=SUSPECT, severity=MEDIUM,
                summary=msg.ARP_REPLY_SPIKE_RATE % (rate, base),
                evidence={"replies": c_rep - p_rep, "seconds": round(span, 1),
                          "per_second": round(rate, 3), "baseline_per_second": round(base, 3),
                          "source": "netstat -s -p arp"},
                # 네트워크에 새로 붙으면 ARP 를 몰아친다. 흔들림 직후의
                # 폭주는 그 과정으로 설명된다. 다만 VPN 은 L2 를 흔들지 않는다 —
                # 터널이 오르내린다고 세그먼트에 ARP 응답이 쏟아지지는 않으므로
                # vpn_change 로는 이것을 설명하지 않는다. 설명으로 쓰면 VPN 이
                # 한 번 끊길 때마다 ARP 스푸핑을 숨길 창이 열린다.
                attribution=(ctx.quality_attribution() if ctx.moved
                             else (ctx.settling if ctx.settling != "vpn_change" else None)),
            ))

    # --- 커널이 기록한 MAC 치환 ---
    # 폴링은 "지금 값"만 본다. 두 주기 사이에 바뀌었다가 되돌아간 치환은
    # 캐시에 흔적이 없다. 커널 로그는 그 순간을 옛 MAC·새 MAC 과 함께 남긴다.
    # 기본값에서는 꺼져 있다 — 이 기기에서 24시간 동안 0건을 확인했다.
    events = cur.get("arp", "log_events")
    if events:
        seen = set(ctx.state.get("arp_log_seen") or [])
        gw = unwrap(cur.get("arp", "gateway_mac"))
        fresh = []
        for e in events:
            key = "%s|%s|%s" % (e.get("ts"), unwrap(e.get("ip")), unwrap(e.get("cur")))
            if key in seen:
                continue
            seen.add(key)
            fresh.append(e)
        # 창이 겹치므로 본 것을 기억한다. 무한정 쌓이지 않게 잘라 둔다.
        ctx.state["arp_log_seen"] = sorted(seen)[-200:]

        moved = [e for e in fresh if e.get("kind") == "moved"]
        denied = [e for e in fresh if e.get("kind") == "permanent_denied"]
        if moved:
            # 게이트웨이가 섞여 있으면 등급을 올린다.
            hits_gw = any(unwrap(e.get("prev")) == gw or unwrap(e.get("cur")) == gw
                          for e in moved) if gw else False
            out.append(Finding(
                axis=SECURITY, kind="ARP_MAC_SUBSTITUTED",
                confidence=CONFIRMED,
                severity=HIGH if hits_gw else MEDIUM,
                summary=(msg.ARP_MAC_SUBSTITUTED_GW if hits_gw
                         else msg.ARP_MAC_SUBSTITUTED) % len(moved),
                evidence={"events": moved, "source": "log show (kernel)"},
                # 이동으로 설명되지 않는다. 커널이 기록한 사실이다.
                attribution=None,
            ))
        if denied:
            out.append(Finding(
                axis=SECURITY, kind="ARP_PERMANENT_DENIED",
                confidence=CONFIRMED, severity=HIGH,
                summary=msg.ARP_PERMANENT_DENIED % len(denied),
                evidence={"events": denied, "source": "log show (kernel)"},
                attribution=None,
            ))

    # --- 한 MAC 이 여러 IP 를 쥐고 있음 ---
    # 라우터가 대리 응답하는 정상 구성에서도 나온다. 그래서 '가능'에 머문다.
    prev_shared = set((prev.get("arp", "shared_macs") or {}).keys())
    cur_shared = cur.get("arp", "shared_macs") or {}
    for mac, entry in cur_shared.items():
        if mac in prev_shared:
            continue
        count, addresses = _shared_entry(entry)
        # 수집기가 이미 걸러 내지만, 옛 형식으로 뜬 기록을 재생할 때를 위해
        # 판정기도 스스로 확인한다.
        if count < SHARED_MAC_MIN_ADDRESSES:
            continue
        out.append(Finding(
            axis=SECURITY, kind="SHARED_MAC",
            confidence=POSSIBLE, severity=LOW,
            summary=msg.SHARED_MAC % count,
            evidence={"mac": {"id": "mac", "v": mac}, "addresses": addresses,
                      "source": "arp -an -x"},
        ))

    return out
