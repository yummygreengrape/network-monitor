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
# **앞에 있을수록 근본 원인에 가깝다.** 잠자기에서 깨어나면 링크가 붙고,
# 그 뒤에 VPN 이 다시 올라온다. 창이 열려 있는 동안 뒤따라온 약한 사유가
# 강한 사유를 덮어쓰면, 깨어난 직후의 재연결이 "VPN 전환" 으로만 설명된다.
DISRUPTIONS = ("sleep", "iface_change", "network_change", "link_restart", "vpn_change")
SETTLE_SECONDS = 45.0


def rtt_elevated(rtt: Optional[float], base: Optional[float]) -> bool:
    if rtt is None or not base:
        return False
    return float(rtt) > max(RTT_SPIKE_MIN_MS, float(base) * RTT_SPIKE_FACTOR)

# 네트워크가 바뀌면 기준선을 버린다. 이전 네트워크의 정상값을 새 네트워크에
# 적용하면 첫 몇 분이 통째로 오탐이 된다.
VOLATILE_KEYS = ("rtt_ewma", "rtt_high_run", "arp_reply_rate", "gw_fail_streak", "gw_fail_streak_prev",
                 # 네트워크가 바뀌면 그곳의 라우터를 새로 배운다
                 "ipv6_routers_known",
                 "arp_replies_last", "settle_left_s", "settle_reason", "settle_saw_link_gap",
                 # 게이트웨이가 ICMP 에 응답하는지는 네트워크마다 다르다.
                 "icmp_gw", "cycles_on_network", "_liveness_decided", "icmp_fail_run")


def fail_count(value: Any) -> int:
    """상태에 남은 연속 실패 횟수를 읽는다. 믿을 수 없는 값은 0 으로 본다.

    state.json 은 사람이 고치거나 이전 판이 남긴 값일 수 있다. 그대로 int()
    에 넣으면 문자열·None 에서 예외가 나 판정이 통째로 멈춘다. 숫자 문자열
    ("2")도 받지 않는다 — 이 값을 문자열로 쓰는 경로는 없으므로 받아 줄
    이유가 없고, 받아 주면 깨진 상태가 경보를 만들 수 있다.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0
    if value != value or value in (float("inf"), float("-inf")) or value < 0:
        return 0
    return int(value)


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
                    interval: float = 5.0,
                    disrupted: Optional[str] = None) -> Dict[str, Any]:
    """판정 전에 갱신한다. 이번 주기를 포함한 값이어야 하는 것들.

    연속 실패 횟수는 ICMP 가 아니라 liveness 가 고른 방법으로 센다. 그러지
    않으면 ICMP 를 막아 둔 네트워크에서 매 주기가 실패로 쌓인다.
    """
    from .liveness import calibrate, evaluate

    new, decided = calibrate(state, cur)

    # 흔들림이 있었으면 창을 다시 연다. 없으면 흘려보낸다.
    step = float(elapsed) if elapsed and elapsed > 0 else float(interval)
    # disrupted 는 귀속 목록에 넣지 않고 안정화 창만 여는 사유다. 링크가
    # 실제로 끊겼다 붙은 것은 물리적 사건이라 ARP 폭주·리졸버 재설치를
    # 동반한다. 하지만 이것을 귀속으로 쓰면 SSID 를 아는데도 정체성 판정이
    # 통째로 덮인다 (evil twin 이 링크를 한 번 끊고 들어오면 끝난다).
    # 그래서 "설명" 이 아니라 "안정화 중" 으로만 쓴다.
    fresh = [a for a in DISRUPTIONS if a in (attributions or [])]
    if disrupted in DISRUPTIONS and disrupted not in fresh:
        fresh.append(disrupted)
    if fresh:
        new["settle_left_s"] = SETTLE_SECONDS
        # **창의 사유 하나로는 "링크가 끊긴 것을 봤는가" 를 알 수 없다.**
        # settle_reason 은 가장 근본에 가까운 사유 하나만 남기므로, 잠자기와
        # 링크 단절이 겹치면 link_restart 가 지워진다. 그 뒤에 "링크가 끊겼다"
        # 고 말해도 되는지 판단하려면 관측 사실을 따로 실어야 한다.
        if "link_restart" in fresh:
            new["settle_saw_link_gap"] = True
        open_reason = state.get("settle_reason") if state.get("settle_left_s") else None
        candidates = fresh + ([open_reason] if open_reason else [])
        # 열려 있던 사유와 새 사유 중 더 근본에 가까운 쪽을 남긴다
        new["settle_reason"] = min(candidates, key=DISRUPTIONS.index)
    else:
        left = float(state.get("settle_left_s", 0.0)) - step
        if left > 0:
            new["settle_left_s"] = round(left, 1)
        else:
            new.pop("settle_left_s", None)
            new.pop("settle_reason", None)
            new.pop("settle_saw_link_gap", None)
    new["_liveness_decided"] = decided

    # 지연이 이만큼 연속으로 높았는가. 판정 시점에 이번 주기가 포함돼야 하므로
    # 여기서 센다. rtt_ewma 는 아직 이번 값이 섞이지 않은 직전 기준선이다.
    if rtt_elevated(cur.get("link", "gateway_rtt_ms"), state.get("rtt_ewma")):
        new["rtt_high_run"] = int(state.get("rtt_high_run", 0)) + 1
    else:
        new["rtt_high_run"] = 0

    _, alive = evaluate(cur, new)
    if alive is True:
        # **초기화 직전 값을 남긴다.** 이 함수는 판정보다 먼저 돌므로, 그냥
        # 0 으로 만들면 복구 판정이 "얼마나 끊겼었는지" 를 영영 알 수 없다.
        # 실제로 그래서 FIRST_HOP_RECOVERED 가 한 번도 뜨지 않았다
        # (양쪽 기계 전체 기록: 무응답 10건, 복구 0건).
        new["gw_fail_streak_prev"] = fail_count(state.get("gw_fail_streak"))
        new["gw_fail_streak"] = 0
    elif alive is False:
        new["gw_fail_streak"] = fail_count(state.get("gw_fail_streak")) + 1
        new["gw_fail_streak_prev"] = 0
    return new


# 링크가 없는 주기에 **이미 알린** 끊김. `{공급자: 끊긴 시각}` 이다.
# 표시를 남기는 것은 그 주기의 판정이고(netmon/detect/vpn.py 의 without_link),
# 지우는 것은 여기다 — 끊김의 시작·끝을 아는 것이 이 파일이기 때문이다.
# **없어도 동작한다** — 없거나 모양이 깨졌으면 종전처럼 판정한다.
VPN_REPORTED_KEY = "vpn_down_reported"


def update_vpn_down(state: Dict[str, Any], cur: Observation,
                    judged: bool = True) -> Dict[str, Any]:
    """공급자별로 "언제부터 끊겨 있는가" 를 갱신한다.

    **판정할 수 없는 주기에서도 불러야 한다.** 링크가 없는 주기는 engine 이
    조기 반환해 `update_baselines` 가 돌지 않았고, 그래서 끊겨 있던 7분 25초가
    `vpn_down_since` 에 들어가지 않아 복구 판정이 "5초 끊김" 으로 적혔다
    (2026-09-21 05:41~05:49 맥북). VPN 상태는 링크가 없어도 수집된다 —
    공급자에게 물어보는 값이라 주 인터페이스가 필요 없다. wireguard·tailscale
    은 물리 링크가 없어도 connected 로 보고될 수 있다.

    `judged=False` 는 그 주기에 판정이 돌지 않았다는 뜻이다. 기록을 지우는
    것은 판정의 몫이므로, 복구가 그 주기에 보이면 지우지 않고 `vpn_down_pending`
    으로 옮겨 다음 판정이 읽게 한다.
    """
    vpn_block = cur.get("vpn")
    if not vpn_block:
        return state
    new = dict(state)
    downs = dict(state.get("vpn_down_since") or {})
    unmeasured = dict(_unmeasured_map(state))
    pending = dict(_pending_map(state))
    reported = dict(reported_map(state))
    for name, st in vpn_block.items():
        if (st or {}).get("state") != "connected":
            downs.setdefault(name, cur.ts)
            # 다시 끊겼으면 알리지 못한 복구는 지나간 일이다. 남겨 두면
            # 다음 복구 판정이 엉뚱한(더 이른) 시각을 적는다.
            pending.pop(name, None)
        elif judged:
            # 복구 판정이 이미 읽고 지나간 뒤다. 다음 끊김에 이월하지 않는다.
            downs.pop(name, None)
            unmeasured.pop(name, None)
            pending.pop(name, None)
            # 이 끊김은 끝났다. 알렸다는 표시도 함께 지운다 — 다음 끊김은
            # 다시 알려야 한다.
            reported.pop(name, None)
        else:
            # **판정하지 않는 주기다.** 여기서 지우면 다음 완전 주기의 복구
            # 판정이 시작 시각을 잃는다 — 고치기 전에는 (갱신도 안 했지만)
            # 적어도 괄호는 남았다. 그래서 지우지 않고 옮겨만 둔다.
            # 끊긴 채로 두지도 않는다 — 공급자가 올라온 뒤의 측정 공백까지
            # 끊긴 시간에 얹히기 때문이다.
            since = downs.pop(name, None)
            if since is not None:
                pending[name] = {"since": since,
                                 "unmeasured": unmeasured.pop(name, 0.0)}
            else:
                unmeasured.pop(name, None)
            reported.pop(name, None)
    new["vpn_down_since"] = downs
    new["vpn_down_unmeasured"] = unmeasured
    if pending:
        new["vpn_down_pending"] = pending
    else:
        new.pop("vpn_down_pending", None)
    if reported:
        new[VPN_REPORTED_KEY] = reported
    else:
        new.pop(VPN_REPORTED_KEY, None)
    return new


def note_unmeasured(state: Dict[str, Any], seconds: float) -> Dict[str, Any]:
    """방금 지나간 측정 공백을, 그동안 끊겨 있던 공급자의 미관측 시간에 더한다.

    **판정보다 먼저 불러야 한다.** 이 주기에 복구 판정이 나면 그 증거가 직전
    공백까지 포함해야 하기 때문이다. 이미 끊겨 있던 공급자에만 더한다 —
    이번 주기에 처음 끊긴 것이라면 그 공백은 끊기기 **전**의 시간이다.
    """
    try:
        span = float(seconds)
    except (TypeError, ValueError):
        return state
    if not span > 0 or span != span or span == float("inf"):
        return state
    downs = state.get("vpn_down_since")
    if not isinstance(downs, dict) or not downs:
        return state
    acc = dict(_unmeasured_map(state))
    for name in downs:
        try:
            prev = float(acc.get(name) or 0.0)
        except (TypeError, ValueError):
            prev = 0.0
        acc[name] = round(prev + span, 1)
    new = dict(state)
    new["vpn_down_unmeasured"] = acc
    return new


def _unmeasured_map(state: Dict[str, Any]) -> Dict[str, Any]:
    """저장된 미관측 누적값. 형태가 깨져 있으면 비어 있는 것으로 본다."""
    acc = state.get("vpn_down_unmeasured")
    return acc if isinstance(acc, dict) else {}


def _pending_map(state: Dict[str, Any]) -> Dict[str, Any]:
    """아직 판정이 읽지 못한 끊김 기록. 형태가 깨져 있으면 비어 있는 것으로 본다."""
    pending = state.get("vpn_down_pending")
    return pending if isinstance(pending, dict) else {}


def reported_map(state: Any) -> Dict[str, Any]:
    """이미 알린 끊김 표시. 형태가 깨져 있으면 비어 있는 것으로 본다.

    판정 쪽(netmon/detect/vpn.py)도 같은 눈으로 읽어야 해서 공개로 둔다.
    """
    if not isinstance(state, dict):
        return {}
    reported = state.get(VPN_REPORTED_KEY)
    return reported if isinstance(reported, dict) else {}


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
    new = update_vpn_down(new, cur)

    replies = cur.get("arp", "replies_received")
    if isinstance(replies, int):
        last = state.get("arp_replies_last")
        if isinstance(last, int) and replies >= last:
            rate = (replies - last) / span
            new["arp_reply_rate"] = round(_ewma(state.get("arp_reply_rate"), rate), 4)
        new["arp_replies_last"] = replies

    return new
