"""VPN 판정 — 상태 전환과 끊김 원인.

원본 스크립트는 끊김 원인을 하나만 골랐다(WIFI / WARP_PATH / NETWORK_CHANGE /
SLEEP / ARP_ANOMALY). 여기서는 고르지 않는다. 대신 한 번의 끊김이 두 축에
따로 기록된다.

  연결 품질  VPN_DISCONNECTED   연결이 끊겼다
  보안       VPN_PROTECTION_LOST 신뢰할 수 없는 네트워크에서 보호가 사라졌다

"왜 끊겼나"는 분류가 아니라 **근거**로 붙는다. 같은 주기의 첫 홉 상태와
억제 사유를 함께 기록하므로, 나중에 판단이 틀렸다고 생각되면 되짚을 수 있다.
원인을 하나 골라 적으면 그 순간 나머지 근거가 사라진다.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..liveness import evaluate
from ..model import (CONFIRMED, INFO, INFO_SEV, LOW, MEDIUM, QUALITY, SECURITY,
                     Finding, Observation)

FEATURE = "detect.vpn"

CONNECTED = "connected"

# 사용자가 직접 끊은 것으로 보이는 사유. 공급자마다 표기가 다르다.
USER_ACTION_HINTS = ("manual", "user", "disabled_by_user", "stopped")

# 개인별 자격증명을 쓰는 방식. 이것만 "다른 사람이 내 트래픽을 볼 수 없다"고
# 말할 수 있다. 나머지는 전부 공유 자격증명이거나 암호화가 없다.
PER_USER_CREDENTIAL = ("enterprise", "eap", "802.1x", "8021x")


def _user_action(reason: Optional[str]) -> bool:
    if not reason:
        return False
    low = reason.lower()
    return any(h in low for h in USER_ACTION_HINTS)


def _network_is_untrusted(cur: Observation) -> Optional[bool]:
    """이 네트워크에서 보호가 사라지는 것이 얼마나 위험한가.

    None 은 "모른다"다. 유선이거나 암호화 방식을 못 읽은 경우다.
    """
    wifi = cur.get("wifi") or {}
    if not wifi.get("applicable"):
        return None
    sec = (wifi.get("security") or "").lower()
    if not sec:
        return None
    # 접미사 없는 "WPA2" 도 사실상 Personal 이다. 개인별 자격증명이라는 근거가
    # 있을 때만 신뢰 쪽으로 보낸다 — 모르면 위험한 쪽으로 친다.
    if any(t in sec for t in PER_USER_CREDENTIAL):
        return False
    return True


def _down_reason(cur: Observation, ctx, state: Dict[str, Any]) -> Dict[str, Any]:
    """끊김과 함께 남길 근거. 원인을 하나로 단정하지 않는다."""
    method, alive = evaluate(cur, ctx.state)
    return {
        "provider_reason": state.get("reason"),
        "first_hop_method": method,
        "first_hop_alive": alive,
        "attributions": list(ctx.attributions),
    }


def _likely(cur: Observation, ctx, state: Dict[str, Any]) -> str:
    """가장 그럴듯한 설명. 판정을 덮어쓰지 않고 요약문에만 쓴다."""
    if _user_action(state.get("reason")):
        return "사용자가 직접 끊은 경우"
    if ctx.has("sleep"):
        return "잠자기"
    if ctx.moved:
        return "네트워크 이동"
    _, alive = evaluate(cur, ctx.state)
    if alive is False:
        return "첫 홉이 응답하지 않음 — 무선 구간 문제"
    if alive is True:
        return "첫 홉은 정상 — 터널 경로 문제"
    return "판단 근거 부족"


def detect(prev: Optional[Observation], cur: Observation, ctx) -> List[Finding]:
    out: List[Finding] = []
    cur_vpn = cur.get("vpn")
    if not cur_vpn or prev is None:
        return out
    prev_vpn = prev.get("vpn") or {}

    for name in sorted(cur_vpn):
        cur_st = cur_vpn[name] or {}
        prev_st = prev_vpn.get(name)
        if not prev_st:
            continue
        was, now = prev_st.get("state"), cur_st.get("state")
        if was == now:
            continue

        # 상태를 알 수 없게 된 것은 끊김이 아니다. 조회 실패일 수 있다.
        if now == "unknown" or was == "unknown":
            out.append(Finding(
                axis=INFO, kind="VPN_STATE_UNKNOWN",
                confidence=CONFIRMED, severity=INFO_SEV,
                summary="%s 의 상태를 확인하지 못했습니다 (%s → %s)." % (name, was, now),
                evidence={"provider": name, "prev": prev_st, "cur": cur_st},
            ))
            continue

        if was == CONNECTED and now != CONNECTED:
            user = _user_action(cur_st.get("reason"))
            attribution = "user_action" if user else ctx.quality_attribution()
            evidence = _down_reason(cur, ctx, cur_st)
            evidence["provider"] = name
            likely = _likely(cur, ctx, cur_st)

            out.append(Finding(
                axis=QUALITY, kind="VPN_DISCONNECTED",
                confidence=CONFIRMED,
                severity=INFO_SEV if user else MEDIUM,
                summary="%s 연결이 끊겼습니다. 가장 그럴듯한 설명은 %s 입니다." % (name, likely),
                evidence=evidence,
                attribution=attribution,
            ))

            # 보호가 사라진 것은 별개 사건이다. 사용자가 직접 끊었어도
            # "지금 보호받고 있지 않다"는 사실은 남는다.
            untrusted = _network_is_untrusted(cur)
            if untrusted is not False:
                out.append(Finding(
                    axis=SECURITY, kind="VPN_PROTECTION_LOST",
                    confidence=CONFIRMED,
                    severity=LOW if (user or untrusted is None) else MEDIUM,
                    summary=("%s 가 끊겨서 트래픽이 터널 밖으로 나가고 있습니다. "
                             "이 네트워크는 같은 L2 에 있는 다른 기기가 들여다볼 수 있는 곳입니다."
                             % name) if untrusted else
                            ("%s 가 끊겼습니다. 이 네트워크를 신뢰할 수 있는지는 "
                             "판단하지 못했습니다." % name),
                    evidence={"provider": name,
                              "wifi_security": (cur.get("wifi") or {}).get("security"),
                              "untrusted_network": untrusted,
                              "user_action": user},
                    attribution="user_action" if user else None,
                ))

        elif was != CONNECTED and now == CONNECTED:
            since = (ctx.state.get("vpn_down_since") or {}).get(name)
            dur = ""
            if since:
                dur = " (%s 부터)" % since[11:19]
            out.append(Finding(
                axis=QUALITY, kind="VPN_RECONNECTED",
                confidence=CONFIRMED, severity=INFO_SEV,
                summary="%s 가 다시 연결됐습니다%s." % (name, dur),
                evidence={"provider": name, "down_since": since,
                          "prev_state": was},
                attribution=ctx.quality_attribution(),
            ))
        else:
            out.append(Finding(
                axis=INFO, kind="VPN_STATE_CHANGED",
                confidence=CONFIRMED, severity=INFO_SEV,
                summary="%s 상태가 바뀌었습니다 (%s → %s)." % (name, was, now),
                evidence={"provider": name, "prev": was, "cur": now},
            ))

    return out
