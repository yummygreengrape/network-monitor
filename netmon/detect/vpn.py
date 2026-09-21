"""VPN 판정 — 상태 전환과 끊김 원인.

원본 스크립트는 끊김 원인을 하나만 골랐다(WIFI / WARP_PATH / NETWORK_CHANGE /
SLEEP / ARP_ANOMALY). 여기서는 고르지 않는다. 대신 한 번의 끊김이 두 축에
따로 기록된다.

  연결 품질  VPN_DISCONNECTED   연결이 끊겼다
  보안       VPN_PROTECTION_LOST 신뢰할 수 없는 네트워크에서 보호가 사라졌다

공급자가 `connecting` 을 보고한 전환도 같은 두 판정으로 남지만, 요약문은
"끊김" 이 아니라 재협상이라고 적는다. 터널 밖으로 나간 사실은 같으므로
보호 상실 판정의 등급과 조사 개시는 달라지지 않는다.

"왜 끊겼나"는 분류가 아니라 **근거**로 붙는다. 같은 주기의 첫 홉 상태와
억제 사유를 함께 기록하므로, 나중에 판단이 틀렸다고 생각되면 되짚을 수 있다.
원인을 하나 골라 적으면 그 순간 나머지 근거가 사라진다.
"""
from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional

from .. import messages as msg
from .. import wifi_security
from ..liveness import ICMP, evaluate
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
    evidence = {
        "provider_reason": state.get("reason"),
        "provider_state": state.get("state"),
        "first_hop_method": method,
        "first_hop_alive": alive,
        "attributions": list(ctx.attributions),
    }
    evidence.update(_probe_evidence(cur))
    return evidence


def _probe_evidence(cur: Observation) -> Dict[str, Any]:
    """첫 홉 증거가 1발인가, 다발인가, 아예 없는가.

    **판별은 합친 관측의 `mode` 로 한다.** `link.first_hop_probes` 는 이번
    주기에 띄우려 한 ping **명령**의 수이고(collect/link.collect), 실제로
    보낸 발 수와 그것들이 하나로 합쳐졌는지는 결과 쪽이 적는다
    (`mode`·`sent`·`loss_pct` 는 collect/link.merge_probes 만 만든다).
    손실률도 합친 관측에만 있으므로 근거를 그쪽으로 통일한다.

    **재지 않은 주기를 1발로 세지 않는다.** 게이트웨이를 못 찾으면 수집기가
    `results` 를 아예 만들지 않고, 수집이 실패하면 link 블록이 비어 있다.
    그때 "1발 ping" 이라고 적으면 보내지도 않은 측정을 증거로 내세우게 된다.

    다발 주기의 `reachable`·`rtt_ms` 는 **첫 발 기준**이므로(AC-1b), 손실
    수를 함께 남기지 않으면 3발 중 2발이 빠진 주기도 "첫 홉은 응답함" 으로만
    남는다.
    """
    results = cur.get("link", "results")
    gw = results.get("gateway") if isinstance(results, dict) else None
    if not isinstance(gw, dict):
        return {"first_hop_probe_mode": "unmeasured"}
    if gw.get("mode") != "burst":
        # 다발에 손실을 싣는 이유가 여기에도 같이 적용된다 — `ping_count` 를
        # 올려 둔 주기는 몇 발이 빠졌는지가 요약문에 나오지 않으므로,
        # 근거에서라도 읽을 수 있어야 한다.
        single: Dict[str, Any] = {"first_hop_probe_mode": "single"}
        replies = gw.get("replies")
        if isinstance(replies, int) and not isinstance(replies, bool):
            single["first_hop_replies"] = replies
        loss = gw.get("loss_pct")
        if isinstance(loss, (int, float)) and not isinstance(loss, bool):
            single["first_hop_loss_pct"] = float(loss)
        return single
    burst: Dict[str, Any] = {"first_hop_probe_mode": "burst",
                             "first_hop_concurrent": bool(gw.get("concurrent"))}
    for src, dst in (("sent", "first_hop_sent"), ("received", "first_hop_received")):
        value = gw.get(src)
        if isinstance(value, int) and not isinstance(value, bool):
            burst[dst] = value
    loss = gw.get("loss_pct")
    if isinstance(loss, (int, float)) and not isinstance(loss, bool):
        burst["first_hop_loss_pct"] = float(loss)
    return burst


def _probe_phrase(evidence: Dict[str, Any]) -> str:
    """첫 홉 증거의 성격을 요약문에 드러내는 한 문장.

    측정하지 않은 주기와, 다발인데 발 수를 읽지 못한 경우에는 아무 말도
    하지 않는다 — 없는 증거를 적거나, 모르는 것을 1발로 적지 않는다.
    """
    mode = evidence.get("first_hop_probe_mode")
    if mode == "single":
        # **발 수를 주장하지 않는다.** 관측에 남는 것은 받은 수와 손실률뿐이라
        # (collect/link.parse_ping), `ping_count` 를 올려 둔 주기가 전부
        # 손실되면 1발이었는지 5발이었는지 구분할 수 없다. 끊김 주기가 바로
        # 그 경우다. 받은 수·손실률은 근거에 싣는다.
        return msg.FIRST_HOP_EVIDENCE_ONE_COMMAND
    if mode != "burst":
        return ""
    sent = evidence.get("first_hop_sent")
    if not isinstance(sent, int):
        return ""
    received = evidence.get("first_hop_received")
    loss = evidence.get("first_hop_loss_pct")
    if isinstance(received, int) and isinstance(loss, float):
        return msg.FIRST_HOP_EVIDENCE_BURST % (sent, received, loss)
    return msg.FIRST_HOP_EVIDENCE_BURST_PLAIN % sent


# 요약문에 그대로 인용해도 되는 공급자 사유. **정확히 일치할 때만** 쓴다.
# 사유 문자열에는 터널 엔드포인트의 공인 IP·포트가 섞여 있고, 요약문은
# 가리지 않은 채로 보고서·화면에 그대로 나간다(redact 는 감싼 값만 바꾼다).
# 부분 일치를 허용하면 "No Network via 198.51.100.7:2408" 같은 문자열이
# 통과한다.
QUOTABLE_REASONS = ("No Network",)


def _quotable_reason(reason: Any) -> Optional[str]:
    if not isinstance(reason, str):
        return None
    text = reason.strip()
    return text if text in QUOTABLE_REASONS else None


def _mixed_first_hop(method: str, evidence: Dict[str, Any]) -> bool:
    """다발에서 일부만 응답했는가.

    **ICMP 로 판정하기로 정해진 망에서만 본다.** 가드가 실제로 갈라내는
    경우는 "ARP 로 판정하기로 정해진 망(`icmp_gw` False)인데 ICMP 가 일부만
    응답한 주기" 다 — 그런 망은 게이트웨이가 ICMP 를 걸러내거나 속도 제한을
    걸어 둔 곳이고(netmon/liveness.py 가 그래서 ARP 로 판정한다), 거기서
    나오는 ICMP 손실은 장애의 증거가 아니다. 가드가 없으면 그 주기마다
    "응답이 엇갈림" 이 정확한 설명("첫 홉은 응답함")을 밀어낸다.
    100% 손실은 아래 `0 < received` 에서 이미 걸러지므로 이 가드와 무관하다.
    """
    if method != ICMP or evidence.get("first_hop_probe_mode") != "burst":
        return False
    sent = evidence.get("first_hop_sent")
    received = evidence.get("first_hop_received")
    if not isinstance(sent, int) or not isinstance(received, int):
        return False
    return 0 < received < sent


def _likely(cur: Observation, ctx, state: Dict[str, Any],
            evidence: Optional[Dict[str, Any]] = None) -> str:
    """가장 그럴듯한 설명. 판정을 덮어쓰지 않고 요약문에만 쓴다.

    **안정화 창까지 본다.** VPN 상태 변화는 깨어난 그 주기가 아니라 다음
    주기에 나타난다 — 실측에서 공백은 16:48:58, 끊김은 16:49:03 이었다.
    같은 주기만 보면 "잠자기에서 깨어나는 중" 대신 "첫 홉은 응답함" 이라고
    답하게 된다. 첫 홉이 응답한 것은 맞지만, 그것이 설명은 아니다.
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
    method, alive = evaluate(cur, ctx.state)
    # 다발이 엇갈리면 어느 쪽으로도 단정하지 않는다. 판정이 읽는 값은 첫 발
    # 기준이라(AC-1b), 첫 발만 빠진 주기를 "첫 홉 무응답 — 이 기기와 공유기
    # 사이 구간 문제" 라고 적으면 바로 뒤에 붙는 "응답 2발, 손실 33%" 와
    # 어긋난다. 반대 방향이지만 이것도 근거를 넘어선 단정이다.
    if _mixed_first_hop(method, evidence or {}):
        return msg.WHY_FIRST_HOP_MIXED
    if alive is False:
        return msg.WHY_LINK
    if alive is True:
        # 첫 홉이 응답했다는 **사실**까지만 적는다. 1발(또는 한 묶음) ICMP 가
        # 돌아온 것으로는 로컬 구간과 터널 상대편 구간을 나눌 수 없다 —
        # 같은 증거량에서 quality.cause_note 는 "판별 불가" 라고 적는다.
        return msg.WHY_FIRST_HOP_OK
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


def _duration(seconds: float) -> str:
    """초를 사람이 읽는 표기로. 큰 단위부터 둘까지만 적는다.

    "604800초 끊김" 은 읽는 사람이 다시 나눠야 한다. 1초가 안 되는 시간은
    "0초" 로 반올림하지 않는다 — 있었던 공백을 없었던 것처럼 적게 된다.
    값 자체는 증거(`down_seconds`·`unmeasured_seconds`)에 초 단위 숫자로
    그대로 남는다.
    """
    try:
        total = int(round(max(0.0, float(seconds))))
    except (TypeError, ValueError):
        return msg.DUR_SECONDS % 0
    if total < 1:
        return msg.DUR_UNDER_SECOND
    parts: List[str] = []
    for size, fmt in ((86400, msg.DUR_DAYS), (3600, msg.DUR_HOURS),
                      (60, msg.DUR_MINUTES), (1, msg.DUR_SECONDS)):
        count, total = divmod(total, size)
        if count:
            parts.append(fmt % count)
        if len(parts) == 2:
            break
    return " ".join(parts)


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
        return msg.VPN_SINCE_UNMEASURED % (since[11:19], _duration(down_s),
                                           _duration(unmeasured))
    return msg.VPN_SINCE % since[11:19]


def _down_summary(name: str, now: Any, likely: str,
                  evidence: Dict[str, Any]) -> str:
    """끊김 판정의 요약문.

    셋을 붙인다: 공급자가 보고한 상태(연결 끊김인가 재협상 중인가), 가장
    그럴듯한 설명, 그리고 **첫 홉 증거가 1발인지 다발인지**. 공급자 사유는
    고정 목록과 정확히 일치할 때만 덧붙인다.

    `connecting` 을 "연결 끊김" 이라고 적지 않는다 — 공급자 자신은 다시 맺는
    중이라고 말하고 있다. 판정 종류·등급은 그대로이고(보호 상실 판정과 조사
    개시도 그대로), 바뀌는 것은 문장뿐이다.
    """
    head = msg.VPN_RENEGOTIATING if now == "connecting" else msg.VPN_DISCONNECTED
    parts = [head % (name, likely), _probe_phrase(evidence)]
    quotable = _quotable_reason(evidence.get("provider_reason"))
    if quotable:
        parts.append(msg.VPN_PROVIDER_REASON % quotable)
    return " ".join(p for p in parts if p)


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
            likely = _likely(cur, ctx, cur_st, evidence)

            out.append(Finding(
                axis=QUALITY, kind="VPN_DISCONNECTED",
                confidence=CONFIRMED,
                severity=INFO_SEV if user else MEDIUM,
                summary=_down_summary(name, now, likely, evidence),
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
