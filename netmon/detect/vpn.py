"""VPN 판정 — 상태 전환과 끊김 원인.

원본 스크립트는 끊김 원인을 하나만 골랐다(WIFI / WARP_PATH / NETWORK_CHANGE /
SLEEP / ARP_ANOMALY). 여기서는 고르지 않는다. 대신 한 번의 끊김이 두 축에
따로 기록된다.

  연결 품질  VPN_DISCONNECTED   연결이 끊겼다
  보안       VPN_PROTECTION_LOST 신뢰할 수 없는 네트워크에서 VPN 이 연결 상태를 벗어났다

공급자가 `connecting` 을 보고한 전환도 같은 두 판정으로 남는다. **두 판정의
요약문 모두** "끊김" 이 아니라 재협상이라고 적는다 — 품질 축은
`_down_summary`, 보안 축은 `_protection_summary`. 판정 종류·등급·조사 개시는
두 상태에서 같고 바뀌는 것은 문장뿐이다. 보안 축을 같은 기준으로 맞춘 것은
사용자 결정이다(2026-09-23): 한 주기의 같은 관측값을 두 문장이 다르게 적고
있었다.

"왜 끊겼나"는 분류가 아니라 **근거**로 붙는다. 같은 주기의 첫 홉 상태와
억제 사유를 함께 기록하므로, 나중에 판단이 틀렸다고 생각되면 되짚을 수 있다.
원인을 하나 골라 적으면 그 순간 나머지 근거가 사라진다.
"""
from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional, Tuple

from .. import messages as msg
from .. import wifi_security
from ..baseline import VPN_REPORTED_KEY, reported_map
from ..liveness import ICMP, evaluate, method_label
from ..model import (CONFIRMED, INFO, INFO_SEV, LOW, MEDIUM, PROBE_TIMED_OUT,
                     QUALITY, SECURITY, Finding, Observation)
from ..vpn import ENDPOINT_PROBES_KEY

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
    evidence.update(_endpoint_evidence(cur))
    return evidence


def _endpoint_evidence(cur: Observation) -> Dict[str, Any]:
    """터널 엔드포인트를 이번 주기에 쟀으면 그 결과 (AC-6).

    **재지 않은 주기에는 아무 키도 만들지 않는다.** 동의가 없거나 기능이
    꺼졌거나 주소를 몰랐던 주기를 "무응답" 으로 읽히게 두지 않는다 — 없는
    측정을 근거로 삼는 것이 이 작업이 없애려는 결함이다.

    주소는 수집기가 `ident` 로 감싼 값을 **그대로** 옮긴다. 내보낼 때
    토큰으로 바뀌어야 하기 때문이다 (AC-5, netmon/redact.py).
    요약문에는 넣지 않는다 — 요약문은 가리지 않은 채로 나간다 (AC-6).

    응답이 없다고 해서 "막혔다" 고 적지 않는다. 여기서 말할 수 있는 것은
    "이 주소로 보낸 ICMP 에 응답이 있었는가" 까지다 — 리졸버 ICMP 무응답을
    증거로 쓰지 않기로 한 것과 같은 이유다.

    예외가 하나 있다. 한 끊김의 상한에 닿아 **일부러 보내지 않은** 주기는
    그 사실을 남긴다(`tunnel_endpoint_capped`). 그때도 도달성은 적지
    않는다 — 보내지 않았으므로 아는 바가 없다.

    측정이 실행되지 못했거나 끝나지 못한 주기도 같다. 수집기의 `reachable`
    은 그때 False 로 남지만 그것은 "응답이 없었다" 가 아니라 "아는 바가
    없다" 이므로, **도달성을 적지 않고** 실패 사실만 남긴다. 값으로 적으면
    나가지도 않은 패킷의 무응답을 도달 실패로 기록하게 된다.
    """
    out: Dict[str, Any] = {}
    if (cur.get("link") or {}).get("tunnel_endpoint_capped"):
        out["tunnel_endpoint_capped"] = True
    results = cur.get("link", "results")
    got = results.get("tunnel_endpoint") if isinstance(results, dict) else None
    if not isinstance(got, dict):
        return out
    targets = cur.get("link", "targets")
    addr = targets.get("tunnel_endpoint") if isinstance(targets, dict) else None
    if addr is not None:
        out["tunnel_endpoint"] = addr
    err = got.get("error")
    if err:
        # 수집기가 남기는 문구는 **고정된 낱말**이다 — 실행 실패는
        # `netmon/model.PROBE_*`, 결과를 받지 못한 예외는 예외 종류 이름까지만
        # (collect/link._error_note). 어느 쪽도 대상 주소를 담지 않는다.
        out["tunnel_endpoint_error"] = str(err)[:80]
        return out
    out["tunnel_endpoint_reachable"] = bool(got.get("reachable"))
    rtt = got.get("rtt_ms")
    if isinstance(rtt, (int, float)) and not isinstance(rtt, bool):
        out["tunnel_endpoint_rtt_ms"] = float(rtt)
    return out


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
        # 받은 수는 다발과 **같은 키**로 적는다. 읽는 쪽이 갈래마다 다른
        # 이름을 알아야 하면 증거를 훑는 코드가 한쪽을 빠뜨린다.
        replies = gw.get("replies")
        if not isinstance(replies, int) or isinstance(replies, bool):
            replies = None
        loss = gw.get("loss_pct")
        if not isinstance(loss, (int, float)) or isinstance(loss, bool):
            loss = None
        # 명령이 실행되지 못하면 수집기는 `{"reachable": False, "error": ...}`
        # 만 남긴다(collect/link.collect 의 예외 처리). 그 `reachable` 은
        # "무응답" 이 아니라 "재지 못함" 이다 — 근거로 옮기지 않으면 나가지도
        # 않은 측정이 "첫 홉 무응답" 의 근거로 쓰인다. 다발 갈래와 **같은
        # 키**로 싣는다(단수 `error` 하나뿐이어도 리스트로).
        err = gw.get("error")
        if err:
            single["first_hop_errors"] = [str(err)[:80]]
            if not replies:
                # **재지 못한 주기에는 받은 수도 손실률도 적지 않는다.**
                # `ping()` 은 실행에 실패해도 `parse_ping("")` 의 결과를 그대로
                # 두므로 `replies 0` 과 `loss_pct 100.0` 이 오류 키와 함께
                # 실린다. 그 100% 는 **출력이 비었다는 뜻**이지 잰 손실률이
                # 아닌데, 증거만 기계로 읽는 쪽에는 "손실 100%" 라는 측정값으로
                # 보인다. 남는 실패 목록이 "재지 못했다" 를 그대로 말한다.
                # 다발 쪽은 다르다 — 거기 `sent` 는 실제로 띄운 명령 수이고,
                # 실패도 보낸 것으로 센다는 결정이 기록돼 있다
                # (AC-3·ADV-4, collect/link.merge_probes).
                return single
        if replies is not None:
            single["first_hop_received"] = replies
        if loss is not None:
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
    # 보낸 수는 **띄운 명령 수**다(collect/link.merge_probes). 명령이
    # 실패하거나 제한 시간을 넘기면 패킷이 나가지 않았는데도 손실로 셈된다.
    # 그 사실을 증거로 옮겨야 손실이 네트워크 탓인지 실행 실패 탓인지
    # 가릴 수 있다.
    errors = gw.get("errors")
    if isinstance(errors, list) and errors:
        burst["first_hop_errors"] = [str(e)[:80] for e in errors]
    return burst


def _only_timed_out(evidence: Dict[str, Any]) -> bool:
    """실행 실패 목록이 **전부** "끝나지 못함" 인가.

    두 가지는 뜻이 다르다. 명령을 찾지 못했거나 권한이 없으면 패킷이 한 발도
    나가지 않았고(`PROBE_NOT_RUN`), 제한 시간을 넘긴 것은 나갔을 수도 있는데
    결과를 받지 못한 것이다(`PROBE_TIMED_OUT`). 어느 쪽도 "쟀다" 가 아니지만
    같은 말도 아니므로 요약문에서 뭉개지 않는다.

    하나라도 다른 것이 섞이면 거짓이다 — 목록은 같은 문구끼리 합쳐지므로
    (collect/link.merge_probes) 섞인 주기에 대해 "전부 시간만 넘겼다" 고
    말할 근거가 없다. 그때는 더 약한 주장(실행되지 못한 것이 있다) 쪽으로 간다.
    """
    errors = evidence.get("first_hop_errors")
    if not isinstance(errors, list) or not errors:
        return False
    return all(str(e) == PROBE_TIMED_OUT for e in errors)


def _probe_phrase(evidence: Dict[str, Any]) -> str:
    """첫 홉 증거의 성격을 요약문에 드러내는 한 문장.

    측정하지 않은 주기와, 다발인데 발 수를 읽지 못한 경우에는 아무 말도
    하지 않는다 — 없는 증거를 적거나, 모르는 것을 1발로 적지 않는다.
    """
    mode = evidence.get("first_hop_probe_mode")
    if mode == "single":
        if evidence.get("first_hop_errors"):
            # 명령이 실행되지 못했거나 끝나지 못한 주기다. "ping 명령 한 번"
            # 이라고 적으면 재지 못한 측정을 증거로 내세우게 된다.
            if _only_timed_out(evidence):
                return msg.FIRST_HOP_EVIDENCE_TIMED_OUT
            return msg.FIRST_HOP_EVIDENCE_NOT_RUN
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
    if evidence.get("first_hop_errors"):
        # 실행되지 못한 측정이 섞여 있으면 손실률을 네트워크 손실로 읽을 수
        # 없다. 보낸 수도 주장하지 않는다 — 발 수를 모르면 말하지 않는다는
        # 평소 주기(single) 기준과 같다.
        timed_out = _only_timed_out(evidence)
        if isinstance(received, int) and received > 0:
            if timed_out:
                return msg.FIRST_HOP_EVIDENCE_BURST_TIMED_OUT % received
            return msg.FIRST_HOP_EVIDENCE_BURST_FAILED % received
        if isinstance(received, int):
            # 받은 것이 하나도 없다. 실패 목록은 같은 문구끼리 합쳐지므로
            # (collect/link.merge_probes) 몇 발이 실패했는지 셀 수 없고,
            # 전부 실패했을 수도 있다 — "일부" 라고 적을 근거가 없다.
            if timed_out:
                return msg.FIRST_HOP_EVIDENCE_BURST_TIMED_OUT_NONE
            return msg.FIRST_HOP_EVIDENCE_BURST_NOT_RUN
        return ""
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


def first_hop_not_run(method: str, evidence: Dict[str, Any]) -> bool:
    """이번 주기의 첫 홉을 **재지 못했는가**.

    실행되지 못한 주기(명령을 못 찾음·권한)와 끝나지 못한 주기(제한 시간
    초과)를 함께 본다. 둘의 뜻은 다르지만(`_only_timed_out` 이 문구에서
    가른다) "잰 결과가 아니다" 라는 점은 같고, 여기서 갈리는 것은 구간을
    지목할 수 있느냐다.

    **모듈 밖에서도 쓴다.** 조사 결론(investigate/playbooks)이 끊김마다
    같은 판단을 해야 하는데, 규칙을 그쪽에 다시 적으면 두 판단이 갈린다 —
    같은 끊김을 요약문은 유보하고 결론은 단정하는 상태가 바로 그렇게 났다.

    명령이 실행되지 못하면 수집기는 `reachable` 을 False 로 적는다
    (collect/link.collect). 그 False 는 "무응답" 이 아니라 "재지 못함" 인데,
    liveness 는 둘을 구분하지 않으므로 `first_hop_alive` 가 False 로 나온다.
    그 값을 그대로 요약문에 옮기면 나가지도 않은 패킷이 "이 기기와 공유기
    사이 구간 문제" 의 근거가 된다.

    **ICMP 로 판정하는 망에서만 본다.** ARP 로 판정하는 망의 `alive` 는
    ping 결과에서 오지 않으므로, ping 이 실행되지 못한 것이 그 판정을
    흐리지 않는다 — `_mixed_first_hop` 의 가드와 같은 이유다.

    응답이 하나라도 있으면(다발의 일부 실패) 나간 발이 있었다는 뜻이므로
    여기서 유보하지 않는다. 그쪽은 엇갈림·손실 문구가 맡는다.
    """
    if method != ICMP or not evidence.get("first_hop_errors"):
        return False
    received = evidence.get("first_hop_received")
    if isinstance(received, int) and not isinstance(received, bool):
        return received <= 0
    return True


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
    # 이름표는 `netmon/liveness.py` 것을 그대로 쓴다. `netmon/detect/quality.py`
    # 의 첫 홉 판정 요약문, 조사 결론(`investigate/playbooks.py`)과 같은 말이어야
    # 한다 — 같은 기계의 같은 주기를 셋이 다른 말로 부르면 안 된다.
    label = method_label(method)
    if first_hop_not_run(method, evidence or {}):
        # 재지 못한 주기다. 어느 쪽으로도 단정하지 않는다. 다만 "실행되지
        # 못함"(패킷이 안 나감)과 "끝나지 못함"(결과를 못 받음)은 다른 말이다.
        if _only_timed_out(evidence or {}):
            return msg.WHY_FIRST_HOP_TIMED_OUT
        return msg.WHY_FIRST_HOP_NOT_RUN
    if _mixed_first_hop(method, evidence or {}):
        return msg.WHY_FIRST_HOP_MIXED % label
    if alive is False:
        return msg.WHY_LINK % label
    if alive is True:
        # 첫 홉이 응답했다는 **사실**까지만 적고, 그것을 무엇으로 판정했는지
        # 함께 적는다. ARP 로 판정하는 망에서는 같은 주기의 ICMP 가 100%
        # 빠져 있을 수 있어, 기준을 밝히지 않으면 바로 뒤에 붙는 다발 숫자와
        # 모순처럼 읽힌다. 1발(또는 한 묶음) ICMP 가
        # 돌아온 것으로는 로컬 구간과 터널 상대편 구간을 나눌 수 없다 —
        # 같은 증거량에서 quality.cause_note 는 "판별 불가" 라고 적는다.
        return msg.WHY_FIRST_HOP_OK % label
    return msg.WHY_UNKNOWN


def _tunnel_off_findings(name: str, prev_st: Dict[str, Any], cur_st: Dict[str, Any],
                         cur: Observation, prev: Observation, ctx) -> List[Finding]:
    """연결돼 있는데 터널을 세우지 않는 모드로 바뀐 것.

    **끊김이 아니라서 상태 전환 판정에 걸리지 않는다.** DNS only 모드에서도
    공급자는 "연결됨" 을 보고하므로, 터널의 보호가 사라진 사실이 조용히 지나간다
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


def _endpoint_probe_record(state: Any, name: str) -> Dict[str, Any]:
    """이 끊김 동안 터널 엔드포인트로 나간 발 수와 상한에 닿았는지.

    **복구 판정에만 붙인다.** 상한에 닿는 것은 끊김이 이어지는 주기에
    일어나는데 끊김 판정은 전환 주기에만 나므로(이 파일 아래 `judge`),
    상한에 닿았다는 사실은 그대로 두면 관측 표본에만 남고 이벤트에는
    실리지 않는다. 그러면 이벤트만 읽는 쪽에서는 "재지 않은 끊김" 과
    "12발을 다 쓰고 멈춘 끊김" 이 구분되지 않는다.

    읽는 값은 엔진이 세어 둔 `state.json` 의 `ENDPOINT_PROBES_KEY` 다
    (netmon/engine.py 가 쓰고, 이름은 netmon/vpn 이 정한다 — 리터럴을 여기
    따로 적으면 이름을 바꿀 때 이 두 필드만 조용히 사라진다). 그 기록은
    공급자가 다시 연결된 것을 **다음 주기**에 보고 지워지므로, 복구를 알리는
    이 주기에는 아직 남아 있다.

    **기록이 없으면 아무 키도 만들지 않는다.** "0발" 과 "기록이 없다" 는
    다르다 — 기능이 꺼져 있었거나, 주소를 한 번도 못 얻었거나, 판정이 여러
    주기 늦어 기록이 이미 지워진 뒤일 수 있다. 그 셋을 "0발 나갔다" 로
    적으면 관측하지 않은 것을 관측한 것처럼 적는 것이 된다.
    """
    counts = state.get(ENDPOINT_PROBES_KEY) if isinstance(state, dict) else None
    rec = counts.get(name) if isinstance(counts, dict) else None
    shots = rec.get("shots") if isinstance(rec, dict) else None
    if not isinstance(shots, int) or isinstance(shots, bool) or shots < 0:
        return {}
    return {"tunnel_endpoint_shots": shots,
            "tunnel_endpoint_cap_reached": bool(rec.get("capped"))}


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

    `connecting` 을 "연결 끊김" 이라고 적지 않는다 — Warp 의 연결 단계나
    Tailscale 의 Starting 처럼 다시 맺는 중인 상태가 `connecting` 으로 옮겨진다.
    판정 종류·등급은 그대로이고(보호 상실 판정도 나고
    조사 개시도 같다), 바뀌는 것은 문장뿐이다. 보안 축의 같은 규칙은
    `_protection_summary`.
    """
    head = msg.VPN_RENEGOTIATING if now == "connecting" else msg.VPN_DISCONNECTED
    parts = [head % (name, likely), _probe_phrase(evidence)]
    quotable = _quotable_reason(evidence.get("provider_reason"))
    if quotable:
        parts.append(msg.VPN_PROVIDER_REASON % quotable)
    return " ".join(p for p in parts if p)


def _protection_summary(name: str, now: Any, body: str) -> str:
    """보호 상실 판정의 요약문 — 공급자가 보고한 상태 + 이 네트워크의 노출 정도.

    머리말은 `_down_summary` 와 같은 기준으로 가른다: `connecting` 이면 끊겼다고
    적지 않는다. 재협상 동안 이 공급자가 주던 보호가 이어지는지는 공급자 보고만
    으로는 알 수 없어서 그렇게 적는다. 본문은 암호화 방식으로 갈린다(호출하는 쪽).

    **어느 쪽도 트래픽이나 터널 여부를 단정하지 않는다.** 이 판정이 읽는 것은
    공급자의 연결 상태와 사유(사용자가 직접 끊었는지, `_user_action`), 그리고
    이 네트워크의 암호화 방식(이번 주기에 못 읽었으면 같은 인터페이스의 직전
    값, `_security_kind`)이다. 트래픽도 `vpn.<공급자>.tunnel` 도 읽지 않는다 —
    `tunnel` 은 이 시점에 언제나 `None`(모름)이다. 공급자 구현이 연결 상태일
    때만 모드를 조회한다(netmon/vpn/__init__.py 의 `Warp.status`).
    """
    head = (msg.VPN_PROTECTION_LOST_HEAD_RENEGOTIATING if now == "connecting"
            else msg.VPN_PROTECTION_LOST_HEAD)
    return "%s %s" % (head % name, body)


def _no_link_summary(name: str, now: Any, cur_st: Dict[str, Any]) -> str:
    """링크가 없는 주기의 끊김 요약문.

    평소 주기의 `_down_summary` 와 다른 점은 둘이다. **"가장 유력한 설명"을
    고르지 않는다** — 그 설명은 첫 홉 판정과 안정화 창을 읽어서 고르는데
    (`_likely`), 주 인터페이스가 없는 주기에는 첫 홉 측정 대상 자체가 없어
    고를 근거가 없고, 그대로 고르게 두면 "네트워크 이동" 같은 설명이 근거
    없이 붙는다(실측 2026-09-21 05:49:17 이 그랬다). 대신 **링크가 없었다는
    관측 사실**을 적는다. 공급자 사유는 평소와 같은 기준으로만 인용한다(고정
    목록과 정확히 일치할 때만 — 사유 문자열에 주소·포트가 섞여 있고 요약문은
    가려지지 않는다).

    같은 점도 하나 있다. **`connecting` 을 "연결 끊김" 이라고 적지 않는다**
    (AC-9) — 이 경로에도 `connecting` 인 주기가 들어올 수 있다. 링크가 빠지는
    끊김에서 첫 비연결 관측이 `connecting` 일 수 있기 때문이다.
    """
    if now == "connecting":
        parts = [msg.VPN_RENEGOTIATING_NO_LINK % name]
    else:
        parts = [msg.VPN_DISCONNECTED_NO_LINK % (name, now)]
    quotable = _quotable_reason(cur_st.get("reason"))
    if quotable:
        parts.append(msg.VPN_PROVIDER_REASON % quotable)
    return " ".join(parts)


def reported_without_link(state: Any, name: str, since: Any) -> bool:
    """`since` 에 시작한 그 끊김을, 링크가 없던 주기에 이미 알렸는가.

    **끊긴 시각이 같을 때만 참이다.** 표시가 있다는 것만 보고 판단하면 상태
    파일에 남은 옛 표시가 다음 끊김까지 덮는다. 시각은 끊김마다 새로 찍히므로
    (baseline.update_vpn_down 의 setdefault), 같은 시각이면 같은 끊김이다.

    표시를 남기는 곳은 `without_link` 하나뿐이다. 그래서 이 값이 참이면
    "이 끊김의 시작을 링크가 없던 주기에 알렸다" 가 확인된 사실이 된다.
    """
    return _is_ts(since) and reported_map(state).get(name) == since


def already_reported(state: Any, name: str) -> bool:
    """지금 이어지고 있는 끊김을, 링크가 없던 주기에 이미 알렸는가."""
    downs = state.get("vpn_down_since") if isinstance(state, dict) else None
    since = downs.get(name) if isinstance(downs, dict) else None
    return reported_without_link(state, name, since)


def without_link(prev_vpn: Any, cur: Observation,
                 state: Dict[str, Any],
                 network: Optional[str] = None) -> Tuple[List[Finding], Dict[str, Any]]:
    """주 인터페이스가 없는 주기에 시작된 끊김을 알린다. (판정 목록, 새 상태).

    engine 은 그런 주기를 조기 반환한다 — 주 인터페이스가 없는 주기의
    경로·리졸버·ARP 는 "없음" 일 뿐이라, 그대로 견주면 링크가 깜빡일 때마다
    바뀐 것처럼 보이기 때문이다(netmon/detect 의 `is_complete`). 관측이
    비어서가 아니다 — 아래 문단에 적었듯 수집 단계는 전부 돈다.

    그 조기 반환 때문에 **끊김 자체가 기록에 남지 않았다**: 2026-09-21 하루의
    끊김 17구간 중 처음부터 끝까지 링크가 없던 4구간
    (01:57·03:51·11:45·23:57 UTC)은 VPN 판정이 한 건도 나지 않았고, 05:41 구간은
    링크가 돌아온 마지막 주기에야(7분 25초 뒤) 한 건 났다.
    이벤트만 읽는 쪽에는 끊김이 실제보다 적게 보인다.

    **여기서 되살리는 것은 "끊겼다"는 사실 하나뿐이다.** 근거로 쓰는 값은
    공급자가 보고한 상태와 사유뿐이다(VPN 상태는 링크가 없어도 수집된다 —
    공급자에게 묻는 값이라 주 인터페이스가 필요 없다). 첫 홉·리졸버·Wi-Fi 는
    **읽지 않는다.** 그 주기에 관측이 없어서가 아니다 — 수집 단계는 전부 돌고
    엔진은 그런 주기에 Wi-Fi 를 일부러 더 읽는다(netmon/engine.py 의
    `wifi_fallback_dev`, `link_active`·암호화 방식이 거기서 나온다). 여기서
    읽지 않기로 한 것이고, 요약문도 그렇게 적는다.
    보호 상실(`VPN_PROTECTION_LOST`)을 여기서 내지 않는 것은 다른 이유다 —
    그 판정은 이 네트워크의 암호화 방식(`wifi.security`)을 읽어야 하는데, 그
    주기의 Wi-Fi 관측은 주 인터페이스로서 본 값이 아니고(`is_primary` False,
    netmon/collect/wifi.py) 값이 비어 있을 수 있다.

    **비교 대상은 직전 주기의 VPN 블록**이다. 판정하지 않은 주기도 포함한다 —
    링크가 없는 동안에도 VPN 상태는 계속 수집되므로, 끊긴 순간을 볼 수 있는
    유일한 비교 대상이다. 직전 주기를 모르면(프로세스의 첫 주기) 아무것도
    알리지 않는다. "모른다" 와 "방금 끊겼다" 는 다르다.
    """
    out: List[Finding] = []
    cur_vpn = cur.get("vpn")
    if (not isinstance(cur_vpn, dict) or not isinstance(prev_vpn, dict)
            or not isinstance(state, dict)):
        return out, state
    reported = dict(reported_map(state))
    marked = False
    for name in sorted(cur_vpn):
        cur_st = cur_vpn[name] or {}
        now, was = cur_st.get("state"), (prev_vpn.get(name) or {}).get("state")
        if was != CONNECTED or now == CONNECTED:
            continue
        # 상태를 읽지 못한 것은 끊김이 아니다. 평소 주기에서도 조회 실패는
        # VPN_STATE_UNKNOWN 으로 갈라 두었고, 링크가 없는 주기에는 그 조회가
        # 실패하기 더 쉽다.
        if not now or now == "unknown":
            continue
        since, _acc = _down_record(state, name)
        if not _is_ts(since):
            # 여기까지 왔으면 이번 주기에 처음 끊긴 것이다(engine 이 먼저
            # baseline.update_vpn_down 을 부른다). 그래도 상태 파일이 깨져
            # 있을 수 있으므로 이번 주기의 시각으로 둔다.
            since = cur.ts
        user = _user_action(cur_st.get("reason"))
        out.append(Finding(
            axis=QUALITY, kind="VPN_DISCONNECTED",
            confidence=CONFIRMED,
            severity=INFO_SEV if user else MEDIUM,
            summary=_no_link_summary(name, now, cur_st),
            evidence={"provider": name, "provider_state": now,
                      "provider_reason": cur_st.get("reason"),
                      "prev_state": was,
                      # 이 주기에 무엇을 보고 판정했는지 남긴다. 평소 주기의
                      # 근거(첫 홉·귀속)와 **섞이지 않게** 하는 표시이기도 하다.
                      "link_absent": True,
                      "down_since": since},
            # **억제 사유를 붙이지 않는다.** 이 주기에는 귀속 계산 자체가
            # 돌지 않았으므로(engine 이 attributions_for 를 부르기 전에
            # 반환한다), 사유를 적으면 계산하지 않은 설명을 적는 것이 된다.
            attribution="user_action" if user else None,
            network=network,
        ))
        reported[name] = since
        marked = True
    if not marked:
        return out, state
    new = dict(state)
    new[VPN_REPORTED_KEY] = reported
    return out, new


def _recovery_between_complete_observations(name: str, cur: Observation,
                                            ctx) -> List[Finding]:
    """완전한 관측 사이에서 시작되고 끝난 끊김의 복구를 알린다.

    `detect` 는 직전 **완전** 관측과 견준다(engine 이 판정하지 않은 주기를
    `prev` 로 삼지 않는다 — netmon/engine.py 의 `cycle`·`replay`). 끊겨 있던
    주기에 주 인터페이스가 없으면 그 주기는 비교 대상이 되지 않으므로, 끊김이
    통째로 두 완전 관측 사이에 들어가면 `was == now == connected` 라 전환이
    보이지 않는다. 이 갈래가 없을 때 2026-09-21 하루치(관측 15,260개)를
    재생하면 `VPN_DISCONNECTED` 17 건에 `VPN_RECONNECTED` 13 건이었다 —
    시작만 있고 끝이 없는 끊김 4 건이 그 차이다. 게다가 그 끊김의 기록은 이
    주기가 끝날 때 `baseline.update_vpn_down` 이 지우므로, 알리지 않으면 총
    끊긴 시간과 미관측 시간(AC-8)이 어디에도 남지 않는다.

    **알리는 조건은 표시(`vpn_down_reported`)가 이 끊김을 가리키는 것**이다.
    표시를 남기는 곳은 링크가 없던 주기의 `without_link` 하나뿐이므로, 표시가
    있으면 그 끊김의 시작을 그 주기에 알렸다는 것이 확인된다. 기록만 보고
    알리면 저장된 상태를 물려받은 주기처럼 링크와 무관하게 남아 있던 기록까지
    "링크가 없던 끊김" 으로 적게 된다.

    **기록을 지우는 시점은 이 항목에서 바꾸지 않는다.** 판정이 읽은 **뒤**,
    같은 주기의 `baseline.update_baselines` → `update_vpn_down(judged=True)`
    이 지운다. 읽기 전에 지우면 이 판정이 시작 시각을 잃고, 더 늦게 지우면
    다음 끊김이 옛 시작 시각을 물려받는다 — 평소 복구 판정이 기대는 순서와
    같은 자리다.

    **적지 않는 것.** 끊겨 있던 동안의 공급자 상태(`disconnected` 였는지
    `connecting` 이었는지)는 이 판정에 전달되지 않는다. 비교 대상인 직전 완전
    관측은 끊기기 전이라 `connected` 이고, 링크가 없던 주기의 상태는 여기까지
    오지 않는다. 그래서 `prev_state` 를 적지 않고 요약문도 상태를 말하지
    않는다. 원인도 고르지 않는다 — 끊긴 동안의 관측을 읽지 않았다.

    끊긴 시간은 `down_since` 부터 **이 주기까지**로 잰다. 공급자가 링크 없는
    주기에 이미 올라왔던 경우(기록이 `vpn_down_pending` 으로 옮겨진 경우)에는
    그만큼 길게 잡힌다 — DEV-2 가 만든 기존 복구 경로와 같은 셈법이다
    (`_down_record`). 보관 표본 7일치(2026-09-16~22, 관측 85,397개)에서 공급자가
    링크 없는 주기에 `connected` 로 바뀐 주기는 0건이었다 — 걸릴 수 있는
    갈래이되 그 표본에서 걸린 적은 없다.
    """
    since, acc = _down_record(ctx.state, name)
    if not reported_without_link(ctx.state, name, since):
        return []
    down_s = _elapsed_seconds(since, cur.ts)
    unmeasured = _unmeasured_seconds(acc, down_s)
    evidence = {"provider": name, "down_since": since,
                "down_seconds": down_s,
                "unmeasured_seconds": unmeasured,
                # 끊김 판정과 같은 표시다. 이벤트를 쌍으로 읽는 쪽이 같은
                # 키로 두 건을 이을 수 있게 둔다.
                "link_absent": True}
    evidence.update(_endpoint_probe_record(ctx.state, name))
    return [Finding(
        axis=QUALITY, kind="VPN_RECONNECTED",
        confidence=CONFIRMED, severity=INFO_SEV,
        summary=msg.VPN_RECONNECTED_NO_LINK % (
            name, _down_phrase(since, down_s, unmeasured)),
        evidence=evidence,
        # 이 주기에는 귀속 계산이 돌았다(engine 이 attributions_for 를 부른
        # 뒤 run_all 을 부른다). 평소 복구 판정과 같은 값을 붙인다.
        attribution=ctx.quality_attribution(),
    )]


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
            # 전환은 안 보여도 끊김은 있었을 수 있다. 링크가 없던 주기에
            # 시작해 완전한 관측이 돌아오기 전에 끝난 끊김이 여기로 온다.
            if now == CONNECTED:
                out.extend(_recovery_between_complete_observations(name, cur, ctx))
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

            # **이미 알린 끊김은 다시 알리지 않는다.** 링크가 돌아왔는데
            # 공급자는 아직 올라오지 못한 주기가 여기 걸린다 — 직전 완전
            # 관측은 끊기기 **전**이라 여기서는 전환으로 보이지만, 그 끊김은
            # 링크가 없던 주기에 이미 났고 이미 알렸다(without_link).
            # 한 번의 끊김이 두 건으로 적히면, 이 작업이 없애려는 "이벤트만
            # 읽으면 수가 틀린다" 가 반대 방향으로 생긴다.
            # 보호 상실 판정은 그대로 낸다 — 그것은 링크가 돌아온 이 주기에
            # 처음 판정할 수 있는(암호화 방식을 읽어야 하는) 별개 사건이다.
            if not already_reported(ctx.state, name):
                out.append(Finding(
                    axis=QUALITY, kind="VPN_DISCONNECTED",
                    confidence=CONFIRMED,
                    severity=INFO_SEV if user else MEDIUM,
                    summary=_down_summary(name, now, likely, evidence),
                    evidence=evidence,
                    attribution=attribution,
                ))

            # 연결 상태를 벗어난 것은 보안 축에 따로 남긴다. 사용자가 직접
            # 끊었어도 이 판정은 남는다.
            kind = _security_kind(cur, prev)
            if kind != wifi_security.PER_USER:
                if kind in (wifi_security.OPEN, wifi_security.SHARED_PASSIVE):
                    body = msg.VPN_PROTECTION_LOST
                    severity = LOW if user else MEDIUM
                elif kind == wifi_security.SHARED_SAE:
                    # 조용히 읽히지는 않는다. 능동적 가로채기만 가능하므로
                    # 개방형·WPA2 때와 같은 등급으로 올리지 않는다.
                    body = msg.VPN_PROTECTION_LOST_SAE
                    severity = LOW
                else:
                    body = msg.VPN_PROTECTION_LOST_UNKNOWN
                    severity = LOW
                out.append(Finding(
                    axis=SECURITY, kind="VPN_PROTECTION_LOST",
                    confidence=CONFIRMED, severity=severity,
                    summary=_protection_summary(name, now, body),
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
            evidence = {"provider": name, "down_since": since,
                        "down_seconds": down_s,
                        "unmeasured_seconds": unmeasured,
                        "prev_state": was}
            evidence.update(_endpoint_probe_record(ctx.state, name))
            out.append(Finding(
                axis=QUALITY, kind="VPN_RECONNECTED",
                confidence=CONFIRMED, severity=INFO_SEV,
                summary=msg.VPN_RECONNECTED % (name, _down_phrase(since, down_s,
                                                                  unmeasured)),
                evidence=evidence,
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
