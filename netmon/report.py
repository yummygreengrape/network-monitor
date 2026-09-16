"""보고.

축과 확신도를 섞지 않는 것이 이 모듈의 유일한 규칙이다. 보안 판정을
품질 판정 사이에 끼워 넣으면 읽는 사람이 둘을 구분하지 못한다.
"""
from __future__ import annotations

from collections import Counter, OrderedDict
from typing import Any, Dict, Iterable, List, Optional

from . import messages as msg
from .model import CONFIRMED, POSSIBLE, QUALITY, SECURITY, SUSPECT

def conf_labels() -> "OrderedDict[str, str]":
    """확신도 이름표. 언어가 바뀌면 바로 따라가도록 부를 때마다 만든다."""
    return OrderedDict([
        (CONFIRMED, msg.CONF_CONFIRMED),
        (SUSPECT, msg.CONF_SUSPECT),
        (POSSIBLE, msg.CONF_POSSIBLE),
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
    lines.append(msg.REPORT_HEADER % (day, samples_count, s["total"]))

    if exposure:
        lines.append("")
        lines.append(msg.REPORT_EXPOSURE_TITLE)
        for item in exposure:
            lines.append("    %s" % item)

    for axis in (SECURITY, QUALITY, "info"):
        in_axis = [e for e in s["active"] if e.get("axis") == axis]
        if not in_axis:
            continue
        lines.append("")
        lines.append("-- %s --" % AXIS_LABEL.get(axis, axis))
        for conf, label in conf_labels().items():
            group = sorted([e for e in in_axis if e.get("confidence") == conf], key=_sort_key)
            if not group:
                continue
            lines.append("  %s" % label)
            for e in group:
                lines.append(_fmt_event(e))

    invs = [e for e in events if e.get("kind", "").startswith("INVESTIGATION_")]
    if invs:
        lines.append("")
        lines.append(msg.REPORT_INVESTIGATION_TITLE)
        lines.append(msg.REPORT_INVESTIGATION_NOTE)
        for e in invs:
            lines.append("    %s  %-26s %s" % (e.get("ts", "")[11:19],
                                               e.get("kind", "")[len("INVESTIGATION_"):],
                                               e.get("summary", "")))

    if s["suppressed"]:
        lines.append("")
        lines.append(msg.REPORT_SUPPRESSED_TITLE % len(s["suppressed"]))
        lines.append(msg.REPORT_SUPPRESSED_NOTE)
        for reason, n in s["attributions"].most_common():
            lines.append("    %-16s %d건" % (reason, n))

    if not s["active"]:
        lines.append("")
        lines.append(msg.REPORT_NO_ACTIVE)
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
            out.append(msg.EXPOSURE_SHARED_PSK % (wifi.get("security") or "?"))
        elif sec in ("none", "open", ""):
            out.append(msg.EXPOSURE_OPEN)
    if wifi.get("applicable") and wifi.get("location") not in ("granted", "granted-via-helper"):
        out.append(msg.EXPOSURE_IDENTITY_AMBIGUOUS)
    if (data.get("dns") or {}).get("via_loopback"):
        out.append(msg.EXPOSURE_DNS_PROXY)
    return out
