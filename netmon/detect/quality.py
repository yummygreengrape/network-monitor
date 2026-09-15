"""연결 품질 판정 — 첫 홉 도달성과 지연 급변.

보안 축과 섞지 않는다. 여기서 나오는 것은 전부 "연결이 나쁘다"이지
"공격받았다"가 아니다.

도달성은 ICMP 에 기대지 않는다. 이유는 netmon/liveness.py 에 적었다.
"""
from __future__ import annotations

from typing import List, Optional

from ..liveness import ARP, ICMP, LINK, evaluate, signals
from ..model import (CONFIRMED, INFO, INFO_SEV, LOW, MEDIUM, QUALITY, SUSPECT,
                     Finding, Observation)

FEATURE = "detect.quality"

# 기준선 대비 이 배수를 넘으면 급변으로 본다. 절대 하한을 같이 둬서
# 1ms 가 4ms 가 된 것을 사건으로 만들지 않는다.
RTT_SPIKE_FACTOR = 4.0
RTT_SPIKE_MIN_MS = 50.0
FAIL_STREAK_ALERT = 2

METHOD_LABEL = {ARP: "ARP 해석", ICMP: "ICMP 응답", LINK: "링크 상태"}


def detect(prev: Optional[Observation], cur: Observation, ctx) -> List[Finding]:
    out: List[Finding] = []
    attribution = ctx.quality_attribution()

    # --- 도달성 판정 방법이 정해진 순간을 한 번 남긴다 ---
    decided = ctx.state.get("_liveness_decided")
    if decided == ARP:
        out.append(Finding(
            axis=INFO, kind="GATEWAY_ICMP_SILENT",
            confidence=CONFIRMED, severity=INFO_SEV,
            summary="이 네트워크의 게이트웨이는 ICMP 에 응답하지 않는다. ARP 가 정상이므로 "
                    "장애가 아니다. 도달성 판정을 ARP 기준으로 바꾼다.",
            evidence={"cycles": ctx.state.get("cycles_on_network"),
                      "gateway_mac": cur.get("arp", "gateway_mac"),
                      "source": "ping + arp -an -x"},
        ))
    elif decided == ICMP:
        out.append(Finding(
            axis=INFO, kind="GATEWAY_ICMP_OK",
            confidence=CONFIRMED, severity=INFO_SEV,
            summary="게이트웨이가 ICMP 에 응답한다. 도달성과 지연을 ping 으로 판정한다.",
            evidence={"rtt_ms": cur.get("link", "gateway_rtt_ms"), "source": "ping"},
        ))

    if prev is None:
        return out

    method, alive = evaluate(cur, ctx.state)
    streak = int(ctx.state.get("gw_fail_streak", 0))

    if alive is False:
        if streak == FAIL_STREAK_ALERT:
            out.append(Finding(
                axis=QUALITY, kind="FIRST_HOP_UNREACHABLE",
                confidence=CONFIRMED, severity=MEDIUM,
                summary="첫 홉이 연속 %d회 죽어 있다 (%s 기준). 무선 구간 문제다."
                        % (streak, METHOD_LABEL.get(method, method)),
                evidence={"method": method, "streak": streak,
                          "signals": signals(cur),
                          "gateway": cur.get("iface", "default4_gateway")},
                attribution=attribution,
            ))
    elif alive is True and streak >= FAIL_STREAK_ALERT:
        out.append(Finding(
            axis=QUALITY, kind="FIRST_HOP_RECOVERED",
            confidence=CONFIRMED, severity=INFO_SEV,
            summary="첫 홉이 돌아왔다 (%d회 실패 후, %s 기준)."
                    % (streak, METHOD_LABEL.get(method, method)),
            evidence={"method": method, "streak": streak},
            attribution=attribution,
        ))

    # --- 지연 급변 ---
    # ICMP 를 쓸 수 있는 네트워크에서만 의미가 있다.
    if method == ICMP and alive:
        rtt = cur.get("link", "gateway_rtt_ms")
        base = ctx.state.get("rtt_ewma")
        if rtt is not None and base and rtt > max(RTT_SPIKE_MIN_MS, base * RTT_SPIKE_FACTOR):
            out.append(Finding(
                axis=QUALITY, kind="LATENCY_SPIKE",
                confidence=SUSPECT, severity=LOW,
                summary="게이트웨이 왕복 시간이 %.0fms 로 튀었다 (기준 %.0fms)." % (rtt, base),
                evidence={"rtt_ms": rtt, "baseline_ms": round(base, 1), "source": "ping"},
                attribution=attribution,
            ))

    # --- 측정이 멈춘 구간 ---
    if ctx.has("sleep"):
        out.append(Finding(
            axis=INFO, kind="MEASUREMENT_GAP",
            confidence=CONFIRMED, severity=INFO_SEV,
            summary="측정이 %.0f초 동안 멈췄다 (잠자기 또는 프로세스 정지)." % ctx.elapsed,
            evidence={"elapsed_s": round(ctx.elapsed, 1), "interval_s": ctx.interval},
            attribution="sleep",
        ))

    return out
