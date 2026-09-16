"""보고.

축과 확신도를 섞지 않는 것이 이 모듈의 유일한 규칙이다. 보안 판정을
품질 판정 사이에 끼워 넣으면 읽는 사람이 둘을 구분하지 못한다.
"""
from __future__ import annotations

from collections import Counter, OrderedDict
from typing import Any, Dict, Iterable, List, Optional

from .model import CONFIRMED, POSSIBLE, QUALITY, SECURITY, SUSPECT

CONF_LABEL = OrderedDict([
    (CONFIRMED, "확정  — 관측만으로 사실이라고 말할 수 있다"),
    (SUSPECT, "의심  — 기준선과 어긋난다. 양성 오류의 여지가 있다"),
    (POSSIBLE, "가능  — 구조적으로 가능하다. 증거는 없다"),
])
SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
AXIS_LABEL = {SECURITY: "보안", QUALITY: "연결 품질", "info": "참고"}


def _sort_key(e: Dict[str, Any]) -> tuple:
    return (SEV_ORDER.get(e.get("severity"), 9), e.get("ts", ""))


def summarize(events: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    events = list(events)
    active = [e for e in events if not e.get("attribution")]
    suppressed = [e for e in events if e.get("attribution")]
    return {
        "total": len(events),
        "active": active,
        "suppressed": suppressed,
        "by_axis": Counter(e.get("axis") for e in active),
        "by_kind": Counter(e.get("kind") for e in active),
        "attributions": Counter(e.get("attribution") for e in suppressed),
    }


def _fmt_event(e: Dict[str, Any]) -> str:
    ts = e.get("ts", "")[11:19]
    return "    %s  [%-6s] %-28s %s" % (ts, e.get("severity", "?"), e.get("kind", "?"),
                                        e.get("summary", ""))


def render(day: str, events: List[Dict[str, Any]], samples_count: int = 0,
           exposure: Optional[List[str]] = None) -> str:
    s = summarize(events)
    lines: List[str] = []
    lines.append("== %s  관측 %d주기, 판정 %d건" % (day, samples_count, s["total"]))

    if exposure:
        lines.append("")
        lines.append("-- 이 네트워크에서 구조적으로 가능한 것 (증거 없음) --")
        for item in exposure:
            lines.append("    %s" % item)

    for axis in (SECURITY, QUALITY, "info"):
        in_axis = [e for e in s["active"] if e.get("axis") == axis]
        if not in_axis:
            continue
        lines.append("")
        lines.append("-- %s --" % AXIS_LABEL.get(axis, axis))
        for conf, label in CONF_LABEL.items():
            group = sorted([e for e in in_axis if e.get("confidence") == conf], key=_sort_key)
            if not group:
                continue
            lines.append("  %s" % label)
            for e in group:
                lines.append(_fmt_event(e))

    invs = [e for e in events if e.get("kind", "").startswith("INVESTIGATION_")]
    if invs:
        lines.append("")
        lines.append("-- 조사 --")
        lines.append("   유의미한 신호가 잡히면 결론이 날 때까지 계속 본다.")
        for e in invs:
            lines.append("    %s  %-26s %s" % (e.get("ts", "")[11:19],
                                               e.get("kind", "")[len("INVESTIGATION_"):],
                                               e.get("summary", "")))

    if s["suppressed"]:
        lines.append("")
        lines.append("-- 사용자 행동·환경으로 설명되어 억제된 판정 (%d건) --"
                     % len(s["suppressed"]))
        lines.append("   지워지지 않고 남는다. 억제 판단이 틀렸다면 여기서 찾는다.")
        for reason, n in s["attributions"].most_common():
            lines.append("    %-16s %d건" % (reason, n))

    if not s["active"]:
        lines.append("")
        lines.append("  활성 판정 없음.")
    return "\n".join(lines)


def exposure_notes(last_sample: Optional[Dict[str, Any]]) -> List[str]:
    """"가능하지만 증거 없음"을 상시 표시한다.

    아무 일도 없을 때 "이상 없음"만 보여주면, 이 네트워크에서 무엇이
    가능한지가 보이지 않는다.
    """
    if not last_sample:
        return []
    out = []
    data = last_sample.get("data", {})
    wifi = data.get("wifi") or {}
    sec = (wifi.get("security") or "").lower()
    if wifi.get("applicable"):
        if sec.startswith("wpa") and "enterprise" not in sec:
            out.append("공유 비밀번호 Wi-Fi(%s): 같은 비밀번호를 아는 사람은 같은 L2 에 있고, "
                       "ARP·DHCP·RA 조작과 수동 복호가 가능하다." % (wifi.get("security") or "?"))
        elif sec in ("none", "open", ""):
            out.append("암호화 없는 Wi-Fi: 같은 공간의 누구나 평문을 읽을 수 있다.")
    if (data.get("dns") or {}).get("via_loopback"):
        out.append("DNS 가 로컬 프록시를 거친다. VPN·필터의 정상 동작일 수도, "
                   "가로채기일 수도 있다 — 무엇이 듣고 있는지는 이 도구가 판별하지 못한다.")
    return out
