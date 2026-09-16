"""기준선 갱신. 순수 함수 — 입력 상태와 관측만 받는다.

두 단계로 나눈다.

  update_counters()  판정 **전**. 연속 실패 횟수처럼 "이번 주기를 포함해야"
                     판정이 맞는 값.
  update_baselines() 판정 **후**. 평균 지연처럼 "이번 주기를 넣으면 이번
                     급변이 스스로 묻히는" 값.

지수 이동 평균을 쓰는 이유는 장소를 옮겨 다니며 쓰는 도구이기 때문이다.
카페와 사무실의 정상 지연이 다르고, 고정 임계값은 둘 중 한쪽에서 반드시 틀린다.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .model import Observation

EWMA_ALPHA = 0.2

# 왕복 시간 급변 판정. 무선 구간은 한 번씩 튀는 것이 정상이라 한 주기만 보고
# 알리면 소음이 된다. 실측 로그에서 한 시간에 아홉 번까지 떴다.
RTT_SPIKE_FACTOR = 4.0
RTT_SPIKE_MIN_MS = 50.0
RTT_SUSTAIN_CYCLES = 3

# 잠자기·네트워크 이동·VPN 전환 직후에는 리졸버·경로·ARP 가 뒤따라 바뀐다.
# **결과는 원인보다 늦게 온다.** 실측에서 WARP 가 connecting 인 채로 리졸버를
# 설치했고, 상태 전환과 리졸버 변화가 서로 다른 주기에 떨어졌다. 같은 주기만
# 보는 억제는 그것을 놓친다.
DISRUPTIONS = ("sleep", "network_change", "iface_change", "vpn_change")
SETTLE_SECONDS = 45.0


def rtt_elevated(rtt: Optional[float], base: Optional[float]) -> bool:
    if rtt is None or not base:
        return False
    return float(rtt) > max(RTT_SPIKE_MIN_MS, float(base) * RTT_SPIKE_FACTOR)

# 네트워크가 바뀌면 기준선을 버린다. 이전 네트워크의 정상값을 새 네트워크에
# 적용하면 첫 몇 분이 통째로 오탐이 된다.
VOLATILE_KEYS = ("rtt_ewma", "rtt_high_run", "arp_reply_rate", "gw_fail_streak",
                 "arp_replies_last", "settle_left_s", "settle_reason",
                 # 게이트웨이가 ICMP 에 응답하는지는 네트워크마다 다르다.
                 "icmp_gw", "cycles_on_network", "_liveness_decided", "icmp_fail_run")


def _ewma(prev: Optional[float], value: float, alpha: float = EWMA_ALPHA) -> float:
    if prev is None:
        return value
    return alpha * value + (1 - alpha) * prev


def reset_for_new_network(state: Dict[str, Any]) -> Dict[str, Any]:
    new = dict(state)
    for key in VOLATILE_KEYS:
        new.pop(key, None)
    return new


def update_counters(state: Dict[str, Any], cur: Observation,
                    attributions: Optional[List[str]] = None,
                    elapsed: Optional[float] = None,
                    interval: float = 5.0) -> Dict[str, Any]:
    """판정 전에 갱신한다. 이번 주기를 포함한 값이어야 하는 것들.

    연속 실패 횟수는 ICMP 가 아니라 liveness 가 고른 방법으로 센다. 그러지
    않으면 ICMP 를 막아 둔 네트워크에서 매 주기가 실패로 쌓인다.
    """
    from .liveness import calibrate, evaluate

    new, decided = calibrate(state, cur)

    # 흔들림이 있었으면 창을 다시 연다. 없으면 흘려보낸다.
    step = float(elapsed) if elapsed and elapsed > 0 else float(interval)
    if any(a in (attributions or []) for a in DISRUPTIONS):
        new["settle_left_s"] = SETTLE_SECONDS
        new["settle_reason"] = next(a for a in DISRUPTIONS if a in (attributions or []))
    else:
        left = float(state.get("settle_left_s", 0.0)) - step
        if left > 0:
            new["settle_left_s"] = round(left, 1)
        else:
            new.pop("settle_left_s", None)
            new.pop("settle_reason", None)
    new["_liveness_decided"] = decided

    # 지연이 이만큼 연속으로 높았는가. 판정 시점에 이번 주기가 포함돼야 하므로
    # 여기서 센다. rtt_ewma 는 아직 이번 값이 섞이지 않은 직전 기준선이다.
    if rtt_elevated(cur.get("link", "gateway_rtt_ms"), state.get("rtt_ewma")):
        new["rtt_high_run"] = int(state.get("rtt_high_run", 0)) + 1
    else:
        new["rtt_high_run"] = 0

    _, alive = evaluate(cur, new)
    if alive is True:
        new["gw_fail_streak"] = 0
    elif alive is False:
        new["gw_fail_streak"] = int(state.get("gw_fail_streak", 0)) + 1
    return new


def update_baselines(state: Dict[str, Any], cur: Observation,
                     elapsed: Optional[float] = None,
                     interval: float = 5.0) -> Dict[str, Any]:
    """판정 후에 갱신한다. 이번 주기가 기준선에 섞이면 안 되는 것들.

    누적 카운터는 **시간으로 나눠서** 기준선에 넣는다. 주기 사이의 간격은
    일정하지 않다 — 잠자기로 939초가 벌어진 구간의 증가분을 5초 주기의
    증가분과 같은 잣대로 비교해 거짓 경보가 실제로 났다.
    """
    new = dict(state)
    span = float(elapsed) if elapsed and elapsed > 0 else float(interval)

    rtt = cur.get("link", "gateway_rtt_ms")
    if rtt is not None and cur.get("link", "gateway_reachable"):  # ICMP 응답이 있을 때만
        new["rtt_ewma"] = round(_ewma(state.get("rtt_ewma"), float(rtt)), 3)

    # VPN 이 끊긴 시각. 재연결 판정이 직전 값을 읽어야 하므로 판정 뒤에 갱신한다.
    vpn_block = cur.get("vpn")
    if vpn_block:
        downs = dict(state.get("vpn_down_since") or {})
        for name, st in vpn_block.items():
            if (st or {}).get("state") == "connected":
                downs.pop(name, None)
            else:
                downs.setdefault(name, cur.ts)
        new["vpn_down_since"] = downs

    replies = cur.get("arp", "replies_received")
    if isinstance(replies, int):
        last = state.get("arp_replies_last")
        if isinstance(last, int) and replies >= last:
            rate = (replies - last) / span
            new["arp_reply_rate"] = round(_ewma(state.get("arp_reply_rate"), rate), 4)
        new["arp_replies_last"] = replies

    return new
