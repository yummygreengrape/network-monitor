"""실시간 화면.

스스로 측정하지 않는다. 상시 실행 에이전트가 남긴 기록을 읽어서 보여 줄
뿐이다. 화면을 띄운다고 측정이 두 번 일어나면 관측이 서로를 방해한다.

render() 는 순수 함수다 — 시각과 자료를 받아 문자열을 만든다.
"""
from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional

from .model import QUALITY, SECURITY, unwrap

CLEAR = "\033[H\033[2J"
DIM = "\033[2m"
BOLD = "\033[1m"
RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
CYAN = "\033[36m"
OFF = "\033[0m"

SEV_COLOR = {"high": RED, "medium": YELLOW, "low": CYAN, "info": DIM}
AXIS_LABEL = {SECURITY: "보안", QUALITY: "품질", "info": "참고"}


def _age(ts: str, now: datetime.datetime) -> Optional[float]:
    try:
        t = datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc)
    except (ValueError, TypeError):
        return None
    return (now - t).total_seconds()


def _rule(title: str, width: int) -> str:
    body = "─ %s " % title
    return DIM + body + "─" * max(0, width - len(body) - 1) + OFF


def render(now: datetime.datetime, agent: Dict[str, Any],
           last_sample: Optional[Dict[str, Any]], sample_count: int,
           events: List[Dict[str, Any]], open_invs: List[Any],
           rules_summary: str, lines: int = 12, width: int = 84,
           show_suppressed: bool = False, stale_after: float = 60.0) -> str:
    out: List[str] = []

    # --- 머리 ---
    stamp = now.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    if agent.get("pid"):
        state = GREEN + "에이전트 실행 중 (pid %s)" % agent["pid"] + OFF
    elif agent.get("installed"):
        state = YELLOW + "에이전트 등록됨, 실행 대기" + OFF
    else:
        state = DIM + "상시 실행 등록 안 됨" + OFF
    out.append("%snetmon%s  %s    %s" % (BOLD, OFF, stamp, state))

    # --- 지금 ---
    if last_sample:
        d = last_sample.get("data", {})
        iface = d.get("iface") or {}
        wifi = d.get("wifi") or {}
        dns = d.get("dns") or {}
        age = _age(last_sample.get("ts", ""), now)
        # "멈췄다"의 기준은 측정 간격에 따라 다르다. 30초 간격으로 도는
        # 에이전트를 60초마다 멈췄다고 하면 계속 거짓말을 한다.
        stale = age is not None and age > stale_after
        parts = [
            "%s %s" % (iface.get("primary") or "?", iface.get("primary_kind") or ""),
            wifi.get("security") or ("유선" if iface.get("primary_kind") != "wifi" else "?"),
        ]
        if dns.get("via_loopback"):
            parts.append("DNS 로컬 프록시")
        age_txt = "%.0f초 전" % age if age is not None else "?"
        if stale:
            age_txt = YELLOW + age_txt + " ← 갱신이 멈췄습니다" + OFF
        out.append("  %-10s %s   관측 %d주기, 마지막 %s"
                   % ("네트워크", " · ".join(p for p in parts if p),
                      sample_count, age_txt))

        vpn = d.get("vpn") or {}
        if vpn:
            shown = []
            for name, st in sorted(vpn.items()):
                s = st.get("state")
                color = GREEN if s == "connected" else (
                    DIM if s == "unknown" else RED)
                shown.append("%s%s %s%s" % (color, name, s, OFF))
            out.append("  %-10s %s" % ("VPN", " · ".join(shown)))
    else:
        out.append("  " + DIM + "아직 기록이 없습니다" + OFF)

    # --- 조사 ---
    out.append("")
    out.append(_rule("조사", width))
    if open_invs:
        for inv in open_invs:
            out.append("  %s%s%s  %s  %d주기  계기=%s"
                       % (BOLD, inv.kind, OFF, inv.id, inv.cycles, inv.trigger))
            tuned = [e for e in inv.evidence if e.get("what") == "기준 변경"]
            if tuned:
                out.append("    %s기준 %d번 바뀜 — 마지막: %s%s"
                           % (DIM, len(tuned), tuned[-1].get("reason", ""), OFF))
            recent = inv.evidence[-2:]
            for e in recent:
                if e.get("what") == "기준 변경":
                    continue
                out.append("    %s%s  %s%s" % (DIM, e.get("ts", "")[11:19],
                                               e.get("what", ""), OFF))
    else:
        out.append("  %s열린 조사 없음%s" % (DIM, OFF))
    out.append("  %s기준: %s%s" % (DIM, rules_summary, OFF))

    # --- 최근 판정 ---
    out.append("")
    out.append(_rule("최근 판정", width))
    shown = [e for e in events if show_suppressed or not e.get("attribution")]
    if not shown:
        out.append("  %s아직 판정 없음%s" % (DIM, OFF))
    for e in shown[-lines:]:
        color = SEV_COLOR.get(e.get("severity"), "")
        tag = "억제" if e.get("attribution") else ""
        summary = e.get("summary", "")
        room = width - 34
        if len(summary) > room:
            summary = summary[:room - 1] + "…"
        out.append("  %s  %s%-4s %-6s%s %-24s %s%s"
                   % (e.get("ts", "")[11:19],
                      color, AXIS_LABEL.get(e.get("axis"), "?"),
                      e.get("severity", ""), OFF,
                      e.get("kind", ""), summary,
                      (" " + DIM + tag + OFF) if tag else ""))

    out.append("")
    out.append("%sCtrl+C 로 닫습니다. 창을 닫아도 감시는 계속됩니다.%s" % (DIM, OFF))
    return "\n".join(out)
