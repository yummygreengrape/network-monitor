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

import datetime
from typing import Any, Dict, List, Optional

from .. import messages as msg
from .. import wifi_security
from ..liveness import evaluate
from ..model import (CONFIRMED, INFO, INFO_SEV, LOW, MEDIUM, QUALITY, SECURITY,
                     Finding, Observation)

FEATURE = "detect.vpn"

CONNECTED = "connected"

# 사용자가 직접 끊은 것으로 보이는 사유. 공급자마다 표기가 다르다.
USER_ACTION_HINTS = ("manual", "user", "disabled_by_user", "stopped")


def _user_action(reason: Optional[str]) -> bool:
    if not reason:
        return False
    low = reason.lower()
    return any(h in low for h in USER_ACTION_HINTS)


def _security_kind(cur: Observation,
                   prev: Optional[Observation] = None) -> str:
    """이 네트워크에서 보호가 사라지면 누가 무엇을 볼 수 있는가.

    wifi_security 의 분류값을 돌려준다. UNKNOWN 은 "모른다"다 — 유선이거나
    암호화 방식을 못 읽은 경우이고, 이때는 노출을 단정하지 않는다.
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

    return wifi_security.classify(sec)


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


def _tunnel_off_findings(name: str, prev_st: Dict[str, Any], cur_st: Dict[str, Any],
                         cur: Observation, prev: Observation, ctx) -> List[Finding]:
    """연결돼 있는데 터널을 세우지 않는 모드로 바뀐 것.

    **끊김이 아니라서 상태 전환 판정에 걸리지 않는다.** DNS only 모드에서도
    공급자는 "연결됨" 을 보고하므로, 보호가 사라진 사실이 조용히 지나간다
    (2026-09-21 실측). 모드가 바뀐 순간과, 그 모드로 다른 네트워크에 붙은
    순간에만 낸다 — 매 주기 되풀이하지 않는다.
    """
    # **조회 실패(None)를 전환으로 세지 않는다.** 모드 조회가 한 번 실패하면
    # False → None → False 로 흔들리고, 그때마다 medium 보안 판정이 되풀이된다.
    # 같은 모듈이 상태 쪽에서 지키는 원칙("unknown 은 끊김이 아니다")과 같다.
    key = "vpn_tunnel_%s" % name
    was_t = prev_st.get("tunnel")
    if was_t is None:
        was_t = ctx.state.get(key)
    now_t = cur_st.get("tunnel")
    if now_t is None:
        return []
    ctx.state[key] = now_t
    if now_t is not False:
        if was_t is False and now_t is True:
            return [Finding(
                axis=INFO, kind="VPN_TUNNEL_ON", confidence=CONFIRMED, severity=INFO_SEV,
                summary=msg.VPN_TUNNEL_ON % (name, cur_st.get("mode") or "?"),
                evidence={"provider": name, "mode": cur_st.get("mode")},
            )]
        return []
    # SSID 를 못 읽는 기계에서는 다른 장소가 link_restart 로만 나타난다.
    # ctx.moved 가 그 셋을 함께 본다.
    moved = ctx.moved
    if was_t is False and not moved:
        return []

    kind = _security_kind(cur, prev)
    if kind == wifi_security.PER_USER:
        return []
    if kind in (wifi_security.OPEN, wifi_security.SHARED_PASSIVE):
        summary, severity = msg.VPN_TUNNEL_OFF, MEDIUM
    elif kind == wifi_security.SHARED_SAE:
        summary, severity = msg.VPN_TUNNEL_OFF_SAE, LOW
    else:
        summary, severity = msg.VPN_TUNNEL_OFF_UNKNOWN, LOW
    return [Finding(
        axis=SECURITY, kind="VPN_TUNNEL_OFF", confidence=CONFIRMED, severity=severity,
        summary=summary % (name, cur_st.get("mode") or "?"),
        evidence={"provider": name, "mode": cur_st.get("mode"),
                  "wifi_security": (cur.get("wifi") or {}).get("security"),
                  "security_kind": kind,
                  "passively_readable":
                      kind in (wifi_security.OPEN, wifi_security.SHARED_PASSIVE)},
    )]


TS_FMT = "%Y-%m-%dT%H:%M:%SZ"


def _down_record(state: Any, name: str):
    """(끊긴 시각, 미관측 누적값). 둘 다 못 찾으면 (None, None).

    판정하지 않는 주기에 공급자가 올라오면 기록이 `vpn_down_pending` 으로
    옮겨진다(baseline.update_vpn_down). 그 주기에는 판정이 돌지 않으므로,
    복구를 알리는 것은 그다음 완전 주기의 몫이고 여기서 그 보관분을 읽는다.
    """
    if not isinstance(state, dict):
        return None, None
    downs = state.get("vpn_down_since")
    since = downs.get(name) if isinstance(downs, dict) else None
    acc = state.get("vpn_down_unmeasured")
    unmeasured = acc.get(name) if isinstance(acc, dict) else None
    if since is None:
        pending = state.get("vpn_down_pending")
        rec = pending.get(name) if isinstance(pending, dict) else None
        if isinstance(rec, dict):
            since, unmeasured = rec.get("since"), rec.get("unmeasured")
    return since, unmeasured


def _is_ts(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        datetime.datetime.strptime(value, TS_FMT)
    except ValueError:
        return False
    return True


def _elapsed_seconds(since: Any, ts: Any) -> Optional[float]:
    """끊긴 시각부터 지금까지 몇 초인가. 읽을 수 없으면 None.

    상태 파일은 사람이 고칠 수 있고 재시작을 건너뛰어 남는다. 값이 문자열이
    아니거나 앞뒤가 뒤집혀 있으면(미래 시각) 계산하지 않는다 — 음수나
    터무니없는 시간을 적느니 적지 않는 편이 낫다.
    """
    if not isinstance(since, str) or not isinstance(ts, str):
        return None
    try:
        a = datetime.datetime.strptime(since, TS_FMT)
        b = datetime.datetime.strptime(ts, TS_FMT)
    except ValueError:
        return None
    span = (b - a).total_seconds()
    return round(span, 1) if span >= 0 else None


def _unmeasured_seconds(raw: Any, down_s: Optional[float]) -> float:
    """끊겨 있던 시간 중 측정이 비어 있던 몫. 셈이 없으면 0.

    총 끊긴 시간을 모르면 0 으로 둔다 — 경계를 그을 수 없는 구간에 "그중
    얼마" 를 적을 수는 없고, 견줄 상한이 없으면 셈이 어긋났을 때 걸러낼
    방법도 없다.
    """
    if down_s is None:
        return 0.0
    try:
        val = float(raw)
    except (TypeError, ValueError):
        return 0.0
    if not val > 0 or val != val or val == float("inf"):
        return 0.0
    # 총 끊긴 시간보다 클 수는 없다. 상태가 어긋나 있어도 기록이 스스로
    # 모순되지 않게 자른다.
    return round(min(val, down_s), 1)


def _down_phrase(since: Any, down_s: Optional[float], unmeasured: float) -> str:
    """재연결 요약문의 괄호. 공백이 섞였으면 총 시간과 미관측 시간을 함께 적는다.

    시각을 읽을 수 있으면 **끊긴 시간을 계산할 수 없어도 시각은 적는다** —
    시계가 뒤로 점프한 직후에 종전에 나오던 표기가 사라지지 않게 한다.
    시각 자체가 시각이 아닐 때만 괄호를 비운다(잘린 값을 적지 않는다).
    """
    if not _is_ts(since):
        return ""
    if down_s is None:
        return msg.VPN_SINCE % since[11:19]
    if unmeasured > 0:
        return msg.VPN_SINCE_UNMEASURED % (since[11:19], down_s, unmeasured)
    return msg.VPN_SINCE % since[11:19]


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
        out.extend(_tunnel_off_findings(name, prev_st, cur_st, cur, prev, ctx))
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
            kind = _security_kind(cur, prev)
            if kind != wifi_security.PER_USER:
                if kind in (wifi_security.OPEN, wifi_security.SHARED_PASSIVE):
                    summary = msg.VPN_PROTECTION_LOST % name
                    severity = LOW if user else MEDIUM
                elif kind == wifi_security.SHARED_SAE:
                    # 조용히 읽히지는 않는다. 능동적 가로채기만 가능하므로
                    # 개방형·WPA2 때와 같은 등급으로 올리지 않는다.
                    summary = msg.VPN_PROTECTION_LOST_SAE % name
                    severity = LOW
                else:
                    summary = msg.VPN_PROTECTION_LOST_UNKNOWN % name
                    severity = LOW
                out.append(Finding(
                    axis=SECURITY, kind="VPN_PROTECTION_LOST",
                    confidence=CONFIRMED, severity=severity, summary=summary,
                    evidence={"provider": name,
                              "wifi_security": (cur.get("wifi") or {}).get("security"),
                              "security_kind": kind,
                              "passively_readable":
                                  kind in (wifi_security.OPEN, wifi_security.SHARED_PASSIVE),
                              "user_action": user},
                    attribution="user_action" if user else None,
                ))

        elif was != CONNECTED and now == CONNECTED:
            since, acc = _down_record(ctx.state, name)
            down_s = _elapsed_seconds(since, cur.ts)
            unmeasured = _unmeasured_seconds(acc, down_s)
            out.append(Finding(
                axis=QUALITY, kind="VPN_RECONNECTED",
                confidence=CONFIRMED, severity=INFO_SEV,
                summary=msg.VPN_RECONNECTED % (name, _down_phrase(since, down_s,
                                                                  unmeasured)),
                evidence={"provider": name, "down_since": since,
                          "down_seconds": down_s,
                          "unmeasured_seconds": unmeasured,
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
