"""연결 품질 판정 — 첫 홉 도달성과 지연 급변.

보안 축과 섞지 않는다. 여기서 나오는 것은 전부 "연결이 나쁘다"이지
"공격받았다"가 아니다.

도달성은 ICMP 에 기대지 않는다. 이유는 netmon/liveness.py 에 적었다.
"""
from __future__ import annotations

from typing import List, Optional

from .. import messages as msg
from ..baseline import RTT_SUSTAIN_CYCLES, fail_count
from ..liveness import ARP, ICMP, LINK, evaluate, signals
from ..model import (CONFIRMED, INFO, INFO_SEV, LOW, MEDIUM, QUALITY, SUSPECT,
                     Finding, Observation)

FEATURE = "detect.quality"

# 왕복 시간 급변 기준은 baseline 이 갖는다. 연속 횟수를 거기서 세기 때문이다.
# 첫 홉이 이만큼 연속으로 무응답이면 알린다. 예전에는 2(10초)였다.
# 2026-09-20 실측: 2회짜리 공백이 30분 간격으로 되풀이됐는데, 같은 순간
# 공유기를 지나 외부로 나가는 ping 은 전부 성공했다 — 공유기가 자기 앞으로
# 온 ICMP 를 가끔 무시한 것이지 연결이 끊긴 것이 아니었다. 실제 열화
# (2026-09-17, 2.4GHz 혼잡)의 끊김은 4·6·11회 연속이었으므로 3 으로도 잡힌다.
FAIL_STREAK_ALERT = 3
# 경보 기준에 못 미친 짧은 끊김도 흔적은 남긴다. 기준을 3 으로 올리면서 복구
# 판정도 같은 기준을 쓰게 되어, 2회짜리 끊김이 기록에서 통째로 사라졌다.
# 경보(medium)가 아니라 복구 시점의 info 한 건이다. 조사는 열지 않는다.
FAIL_STREAK_BRIEF = 2

METHOD_LABEL = {ARP: "ARP 해석", ICMP: "ICMP 응답", LINK: "링크 상태"}

# "무선 구간 문제" 라고 말할 근거가 있는가. 경보 기준이 아니라 문구를 고르는
# 기준이다. 흔히 쓰는 대략값으로, RSSI -75 dBm 이하나 SNR 20 dB 미만이면
# 약하다고 본다. 예전에는 근거 없이 늘 "무선 구간 문제로 추정" 이라고 적었다
# — 2026-09-20 실측에서 RSSI -33 dBm 그대로인 15초 무응답에도 그렇게 적혔고,
# 유선 기계에서 떴다면 문장 자체가 틀렸다.
WEAK_RSSI_DBM = -75
WEAK_SNR_DB = 20


def cause_note(cur) -> str:
    if not cur.get("wifi", "applicable"):
        return msg.FIRST_HOP_CAUSE_WIRED
    rssi, snr = cur.get("wifi", "rssi"), cur.get("wifi", "snr")
    if not isinstance(rssi, int):
        return msg.FIRST_HOP_CAUSE_UNKNOWN
    if rssi <= WEAK_RSSI_DBM or (isinstance(snr, int) and snr < WEAK_SNR_DB):
        return msg.FIRST_HOP_CAUSE_WEAK % rssi
    return msg.FIRST_HOP_CAUSE_STRONG % rssi


def detect(prev: Optional[Observation], cur: Observation, ctx) -> List[Finding]:
    out: List[Finding] = []
    attribution = ctx.quality_attribution()

    # --- 도달성 판정 방법이 정해진 순간을 한 번 남긴다 ---
    decided = ctx.state.get("_liveness_decided")
    if decided == ARP:
        out.append(Finding(
            axis=INFO, kind="GATEWAY_ICMP_SILENT",
            confidence=CONFIRMED, severity=INFO_SEV,
            summary=msg.GATEWAY_ICMP_SILENT,
            evidence={"cycles": ctx.state.get("cycles_on_network"),
                      "gateway_mac": cur.get("arp", "gateway_mac"),
                      "source": "ping + arp -an -x"},
        ))
    elif decided == ICMP:
        out.append(Finding(
            axis=INFO, kind="GATEWAY_ICMP_OK",
            confidence=CONFIRMED, severity=INFO_SEV,
            summary=msg.GATEWAY_ICMP_OK,
            evidence={"rtt_ms": cur.get("link", "gateway_rtt_ms"), "source": "ping"},
        ))

    if prev is None:
        return out

    method, alive = evaluate(cur, ctx.state)
    streak = fail_count(ctx.state.get("gw_fail_streak"))

    if alive is False:
        if streak == FAIL_STREAK_ALERT:
            out.append(Finding(
                axis=QUALITY, kind="FIRST_HOP_UNREACHABLE",
                confidence=CONFIRMED, severity=MEDIUM,
                summary=msg.FIRST_HOP_UNREACHABLE % (streak, METHOD_LABEL.get(method, method),
                                                  cause_note(cur)),
                evidence={"method": method, "streak": streak,
                          "signals": signals(cur),
                          "rssi": cur.get("wifi", "rssi"), "snr": cur.get("wifi", "snr"),
                          "gateway": cur.get("iface", "default4_gateway")},
                attribution=attribution,
            ))
    else:
        # **복구는 초기화 직전 값으로 판정한다.** 기준선 갱신이 판정보다 먼저
        # 돌면서 streak 을 0 으로 만들기 때문에, 현재 값으로 보면 조건이
        # 영원히 거짓이다 — 실제로 양쪽 기계 전체 기록에서 무응답 10건에
        # 복구 0건이었다.
        was = fail_count(ctx.state.get("gw_fail_streak_prev"))
        if alive is True and was >= FAIL_STREAK_ALERT:
            out.append(Finding(
                axis=QUALITY, kind="FIRST_HOP_RECOVERED",
                confidence=CONFIRMED, severity=INFO_SEV,
                summary=msg.FIRST_HOP_RECOVERED % (was, METHOD_LABEL.get(method, method)),
                evidence={"method": method, "streak": was},
                attribution=attribution,
            ))
        elif alive is True and FAIL_STREAK_BRIEF <= was < FAIL_STREAK_ALERT:
            out.append(Finding(
                axis=QUALITY, kind="FIRST_HOP_BRIEF_GAP",
                confidence=CONFIRMED, severity=INFO_SEV,
                summary=msg.FIRST_HOP_BRIEF_GAP % (was, METHOD_LABEL.get(method, method)),
                evidence={"method": method, "streak": was},
                attribution=attribution,
            ))

    # --- 지연 급변 ---
    # ICMP 를 쓸 수 있는 네트워크에서만 의미가 있다.
    # 한 주기만 보고 알리면 무선 구간의 정상적인 흔들림이 전부 사건이 된다.
    # 연속으로 높을 때 한 번만 알린다.
    if method == ICMP and alive and int(ctx.state.get("rtt_high_run", 0)) == RTT_SUSTAIN_CYCLES:
        rtt = cur.get("link", "gateway_rtt_ms")
        base = ctx.state.get("rtt_ewma")
        out.append(Finding(
            axis=QUALITY, kind="LATENCY_SPIKE",
            confidence=SUSPECT, severity=LOW,
            summary=msg.LATENCY_SPIKE_SUSTAINED % (rtt, base, RTT_SUSTAIN_CYCLES),
            evidence={"rtt_ms": rtt, "baseline_ms": round(base, 1),
                      "cycles": RTT_SUSTAIN_CYCLES, "source": "ping"},
            attribution=attribution,
        ))

    # --- 측정이 멈춘 구간 ---
    if ctx.has("sleep"):
        out.append(Finding(
            axis=INFO, kind="MEASUREMENT_GAP",
            confidence=CONFIRMED, severity=INFO_SEV,
            summary=msg.MEASUREMENT_GAP % ctx.elapsed,
            evidence={"elapsed_s": round(ctx.elapsed, 1), "interval_s": ctx.interval},
            attribution="sleep",
        ))

    return out
