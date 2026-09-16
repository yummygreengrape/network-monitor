"""첫 홉이 살아 있는가 — ICMP 에 기대지 않고 판정한다.

실측에서 확인한 것: 공용 Wi-Fi 의 게이트웨이가 ICMP 에도 TCP 에도 전혀
응답하지 않으면서 ARP 는 정상이고 인터넷도 정상인 경우가 있다. 클라이언트
격리나 ICMP 필터링을 켠 네트워크에서는 흔한 구성이다.

게이트웨이 ping 을 무선 구간 장애의 기준으로 쓰면 그런 네트워크에서는
매 주기가 장애로 기록된다. 그래서 네트워크마다 "이 게이트웨이가 ICMP 에
응답하는가"를 먼저 보정하고, 응답하지 않으면 ARP 해석 여부로 판정을 바꾼다.

신호의 우선순위
  1. ARP 해석   게이트웨이 MAC 이 잡히면 L2 는 살아 있다. 권한도 응답도 필요 없다.
  2. ICMP       이 네트워크에서 한 번이라도 응답한 적이 있을 때만 쓴다.
  3. 링크 상태  인터페이스 자체가 내려갔는지.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from .model import Observation, unwrap

# 이 주기 수만큼 지켜봤는데 ICMP 응답이 한 번도 없고 ARP 는 계속 정상이면
# "이 게이트웨이는 ICMP 에 응답하지 않는다"로 결론짓는다.
CALIBRATION_CYCLES = 5

# ICMP 로 판정하기로 정한 뒤에도, ARP 는 계속 정상인데 ICMP 만 이만큼 연속으로
# 실패하면 판정 기준을 ARP 로 되돌린다. 게이트웨이가 ICMP 속도 제한을 켜거나
# 펌웨어가 바뀌면 그런 일이 생기고, 되돌리지 않으면 영원히 거짓 경보가 난다.
# ARP 까지 함께 죽는 진짜 장애에서는 이 조건이 성립하지 않아 경보가 유지된다.
REVERT_AFTER_ICMP_FAILURES = 20

ARP = "arp"
ICMP = "icmp"
LINK = "link"
UNKNOWN = "unknown"


def signals(obs: Observation) -> Dict[str, Optional[bool]]:
    """이번 주기의 원시 신호. 판정하지 않는다."""
    arp_ok = bool(unwrap(obs.get("arp", "gateway_mac")))
    icmp_ok = obs.get("link", "gateway_reachable")
    wifi = obs.get("wifi") or {}
    link_ok = None
    if wifi.get("applicable"):
        la = wifi.get("link_active")
        if la is not None:
            link_ok = str(la).lower() in ("true", "yes", "1", "active")
    return {"arp": arp_ok, "icmp": icmp_ok, "link": link_ok}


def method_for(state: Dict[str, Any]) -> str:
    """이 네트워크에서 쓸 도달성 판정 방법."""
    icmp_usable = state.get("icmp_gw")
    if icmp_usable is True:
        return ICMP
    if icmp_usable is False:
        return ARP
    return UNKNOWN  # 아직 보정 중


def evaluate(obs: Observation, state: Dict[str, Any]) -> Tuple[str, Optional[bool]]:
    """(쓴 방법, 살아 있는가). 판정할 수 없으면 (방법, None)."""
    sig = signals(obs)
    method = method_for(state)

    if method == ICMP:
        return ICMP, sig["icmp"]
    if method == ARP:
        return ARP, sig["arp"]

    # 보정 중: ARP 가 잡히면 살아 있다고 본다. ICMP 실패만으로는 아직 판정하지 않는다.
    if sig["arp"]:
        return ARP, True
    if sig["icmp"] is True:
        return ICMP, True
    if sig["link"] is False:
        return LINK, False
    return UNKNOWN, None


def calibrate(state: Dict[str, Any], obs: Observation) -> Tuple[Dict[str, Any], Optional[str]]:
    """ICMP 사용 가능 여부를 갱신한다.

    돌려주는 두 번째 값은 결론이 처음 정해진 순간에만 채워진다 —
    그 사실을 한 번 기록하기 위해서다.
    """
    new = dict(state)
    sig = signals(obs)
    new["cycles_on_network"] = int(state.get("cycles_on_network", 0)) + 1

    if state.get("icmp_gw") is True:
        if sig["icmp"] is False and sig["arp"]:
            run_len = int(state.get("icmp_fail_run", 0)) + 1
            new["icmp_fail_run"] = run_len
            if run_len >= REVERT_AFTER_ICMP_FAILURES:
                new["icmp_gw"] = False
                new["icmp_fail_run"] = 0
                return new, ARP
        else:
            new["icmp_fail_run"] = 0
        return new, None

    if sig["icmp"] is True:
        new["icmp_gw"] = True
        if state.get("icmp_gw") is None:
            return new, ICMP
        return new, None

    if state.get("icmp_gw") is None:
        if sig["arp"] and new["cycles_on_network"] >= CALIBRATION_CYCLES:
            new["icmp_gw"] = False
            return new, ARP
    return new, None
