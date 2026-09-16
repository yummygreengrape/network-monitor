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

from .. import messages as msg
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


def _network_is_untrusted(cur: Observation,
                          prev: Optional[Observation] = None) -> Optional[bool]:
    """이 네트워크에서 보호가 사라지는 것이 얼마나 위험한가.

    None 은 "모른다"다. 유선이거나 암호화 방식을 못 읽은 경우다.
    """
    wifi = cur.get("wifi") or {}
    sec = (wifi.get("security") or "") if wifi.get("applicable") else ""

    # 잠에서 깬 직후에는 Wi-Fi 가 아직 붙지 않아 값이 비어 있다. 같은
    # 인터페이스라면 직전에 알던 값을 쓴다 — 모르는 것과 잠깐 못 읽은 것은
    # 다르다. 실측에서 이 때문에 "신뢰 여부 판단 불가" 가 나왔다.
    if not sec and prev is not None:
        p_if, c_if = prev.get("iface", "primary"), cur.get("iface", "primary")
        # 인터페이스가 같거나, 이번 관측에 인터페이스가 아예 없을 때(링크가
        # 사라진 순간) 직전 값을 쓴다. 다른 인터페이스로 바뀐 경우만 제외한다.
        if p_if == c_if or not c_if:
            pw = prev.get("wifi") or {}
            if pw.get("applicable"):
                sec = pw.get("security") or ""

    sec = sec.lower()
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
    """가장 그럴듯한 설명. 판정을 덮어쓰지 않고 요약문에만 쓴다.

    **안정화 창까지 본다.** VPN 상태 변화는 깨어난 그 주기가 아니라 다음
    주기에 나타난다 — 실측에서 공백은 16:48:58, 끊김은 16:49:03 이었다.
    같은 주기만 보면 "잠자기에서 깨어나는 중" 대신 "터널 경로 문제" 라고
    답하게 된다. 첫 홉이 정상인 것은 맞지만, 그것이 설명은 아니다.
    """
    if _user_action(state.get("reason")):
        return msg.WHY_USER
    if ctx.has("sleep"):
        return msg.WHY_SLEEP
    if ctx.settling == "sleep":
        return msg.WHY_WOKE
    if ctx.moved:
        return msg.WHY_MOVED
    if ctx.settling in ("network_change", "iface_change"):
        return msg.WHY_MOVED
    if ctx.settling == "link_restart":
        return msg.WHY_LINK_BACK
    _, alive = evaluate(cur, ctx.state)
    if alive is False:
        return msg.WHY_LINK
    if alive is True:
        return msg.WHY_TUNNEL
    return msg.WHY_UNKNOWN


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
                summary=msg.VPN_STATE_UNKNOWN % (name, was, now),
                evidence={"provider": name, "prev": prev_st, "cur": cur_st},
            ))
            continue

        if was == CONNECTED and now != CONNECTED:
            user = _user_action(cur_st.get("reason"))
            # 억제도 안정화 창까지 본다. 깨어난 직후의 재연결을 장애로 세면
            # 노트북을 여닫을 때마다 끊김이 쌓인다.
            attribution = ("user_action" if user
                           else ctx.quality_attribution() or ctx.settling)
            evidence = _down_reason(cur, ctx, cur_st)
            evidence["provider"] = name
            likely = _likely(cur, ctx, cur_st)

            out.append(Finding(
                axis=QUALITY, kind="VPN_DISCONNECTED",
                confidence=CONFIRMED,
                severity=INFO_SEV if user else MEDIUM,
                summary=msg.VPN_DISCONNECTED % (name, likely),
                evidence=evidence,
                attribution=attribution,
            ))

            # 보호가 사라진 것은 별개 사건이다. 사용자가 직접 끊었어도
            # "지금 보호받고 있지 않다"는 사실은 남는다.
            untrusted = _network_is_untrusted(cur, prev)
            if untrusted is not False:
                out.append(Finding(
                    axis=SECURITY, kind="VPN_PROTECTION_LOST",
                    confidence=CONFIRMED,
                    severity=LOW if (user or untrusted is None) else MEDIUM,
                    summary=((msg.VPN_PROTECTION_LOST if untrusted
                              else msg.VPN_PROTECTION_LOST_UNKNOWN) % name),
                    evidence={"provider": name,
                              "wifi_security": (cur.get("wifi") or {}).get("security"),
                              "untrusted_network": untrusted,
                              "user_action": user},
                    attribution="user_action" if user else None,
                ))

        elif was != CONNECTED and now == CONNECTED:
            since = (ctx.state.get("vpn_down_since") or {}).get(name)
            dur = msg.VPN_SINCE % since[11:19] if since else ""
            out.append(Finding(
                axis=QUALITY, kind="VPN_RECONNECTED",
                confidence=CONFIRMED, severity=INFO_SEV,
                summary=msg.VPN_RECONNECTED % (name, dur),
                evidence={"provider": name, "down_since": since,
                          "prev_state": was},
                attribution=ctx.quality_attribution(),
            ))
        else:
            out.append(Finding(
                axis=INFO, kind="VPN_STATE_CHANGED",
                confidence=CONFIRMED, severity=INFO_SEV,
                summary=msg.VPN_STATE_CHANGED % (name, was, now),
                evidence={"provider": name, "prev": was, "cur": now},
            ))

    return out
