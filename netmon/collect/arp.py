"""ARP 이웃 표와 ARP 통계.

게이트웨이 MAC 변경과 IP 충돌이 여기서 나온다. 통계 카운터의 증가분도
함께 본다 — ARP 응답 수가 갑자기 뛰면 스푸핑 시도의 흔적일 수 있다.
"""
from __future__ import annotations

import re

from typing import Any, Dict, List, Optional

from .. import messages as msg
from ..model import ident
from ..util import OK, BROKEN, Capability, run

NAME = "arp"

INCOMPLETE = ("(incomplete)", "(none)", "incomplete")

# 한 MAC 이 여러 IP 를 쥔 것은 ARP 스푸핑에서 나타나는 모양이지만, 라우터가
# 대리 응답하는 정상 구성에서도 같은 모양이 나온다. 판정은 이 개수 이상일
# 때만 쓴다. 그 아래는 기록해도 판정에 쓰이지 않으면서 자리만 차지한다 —
# 실측에서 IP 2개짜리 항목 224개가 샘플 하나의 22KB, 하루 기록의 59% 를
# 먹고 있었다.
SHARED_MAC_MIN_ADDRESSES = 3
SHARED_MAC_MAX_ADDRESSES = 8    # 판정 근거로 쓰는 만큼만 남긴다
SHARED_MAC_MAX_ENTRIES = 20     # 최악의 경우를 묶어 둔다


def normalize_mac(raw: str) -> str:
    """MAC 을 두 자리씩 채운 표기로 맞춘다.

    macOS `arp` 는 각 옥텟의 앞 0 을 떼고 출력한다 — `00:00:5e:00:53:01` 이
    `0:0:5e:0:53:1` 로 나온다. 그대로 두면 다른 데이터원에서 온 값과 비교할 수
    없고, 누출 검사의 MAC 패턴에도 걸리지 않아 저장소로 새어 들어갈 수 있다.
    """
    parts = raw.strip().lower().split(":")
    if len(parts) != 6 or not all(p and len(p) <= 2 for p in parts):
        return raw.strip().lower()
    try:
        return ":".join("%02x" % int(p, 16) for p in parts)
    except ValueError:
        return raw.strip().lower()


def parse_arp_table(text: str) -> List[Dict[str, Any]]:
    """`arp -an -x` 출력을 파싱한다.

    정상 항목과 미완성 항목의 열 수가 다르지만, 앞의 다섯 열
    (이웃 IP, 링크계층 주소, Expire(O), Expire(I), Netif)은 같다.
    """
    rows: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.rstrip()
        if not line or line.startswith("Neighbor"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        ip, mac, netif = parts[0], parts[1], parts[4]
        if "." not in ip and ":" not in ip:
            continue
        rows.append({
            "ip": ip,
            "mac": None if mac in INCOMPLETE else normalize_mac(mac),
            "iface": netif,
            "expire_o": parts[2],
            "expire_i": parts[3],
        })
    return rows


def parse_arp_stats(text: str) -> Dict[str, int]:
    """`netstat -s -p arp` 의 `<수> <설명>` 줄을 dict 로."""
    out: Dict[str, int] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.endswith(":"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        try:
            n = int(parts[0])
        except ValueError:
            continue
        out[parts[1].strip()] = n
    return out


# 통계 키 이름은 macOS 버전마다 조금씩 다르고 오타도 있다("broadast").
# 그래서 정확한 문자열 대신 부분 일치로 찾는다.
def stat_like(stats: Dict[str, int], *needles: str) -> Optional[int]:
    for key, val in stats.items():
        low = key.lower()
        if all(n.lower() in low for n in needles):
            return val
    return None


def lookup(rows: List[Dict[str, Any]], ip: str, iface: Optional[str] = None) -> Optional[str]:
    for r in rows:
        if r["ip"] == ip and (iface is None or r["iface"] == iface):
            return r["mac"]
    return None


# 커널이 ARP 엔트리의 MAC 을 덮어쓸 때 남기는 경고. **기본값에서는 꺼져 있어
# 아무 흔적도 남지 않는다** — 이 기기에서 24시간 동안 `arp:` 커널 메시지 0건을
# 확인했다. 켜면 옛 MAC 과 새 MAC 을 모두 담은 타임스탬프 사건이 생기는데,
# 이것은 5초 폴링으로는 만들 수 없는 증거다. 폴링은 "지금 값"만 본다.
ARP_LOG_SYSCTL = "net.link.ether.inet.log_arp_warnings"

# `arp: <ip> moved from <old> to <new> on <iface>`
# compact 형식의 앞머리: `2026-09-17 21:03:33.513 Df kernel[0:1a2b] ...`
_STAMP = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)")

_MOVED = re.compile(
    r"arp:\s+(?P<ip>[0-9.]+)\s+moved\s+from\s+(?P<old>[0-9a-fA-F:]+)"
    r"\s+to\s+(?P<new>[0-9a-fA-F:]+)(?:\s+on\s+(?P<iface>\w+))?")
# `arp: <mac> attempts to modify permanent entry for <ip> on <iface>`
_PERMANENT = re.compile(
    r"arp:\s+(?P<mac>[0-9a-fA-F:]+)\s+attempts to modify permanent entry for"
    r"\s+(?P<ip>[0-9.]+)(?:\s+on\s+(?P<iface>\w+))?")


def arp_logging_enabled() -> Optional[bool]:
    """커널 ARP 경고가 켜져 있는가. 못 읽으면 None."""
    r = run(["sysctl", "-n", ARP_LOG_SYSCTL], timeout=3)
    if r.rc != 0:
        return None
    v = r.out.strip()
    return v not in ("", "0") if v.isdigit() or v == "" else None


def parse_arp_log(text: str) -> List[Dict[str, Any]]:
    """커널 로그 줄에서 MAC 치환·영구 엔트리 변경 시도만 뽑는다.

    형식을 못 읽은 `arp:` 줄은 버리지 않고 raw 로 남긴다 — 못 읽은 것을
    없는 것으로 만들면 안 된다.
    """
    out: List[Dict[str, Any]] = []
    for raw in text.splitlines():
        if "arp:" not in raw:
            continue
        st = _STAMP.match(raw.strip())
        when = st.group("ts") if st else None
        m = _MOVED.search(raw)
        if m:
            out.append({"kind": "moved", "ts": when,
                        "ip": ident("ipv4", m.group("ip")),
                        "prev": ident("mac", normalize_mac(m.group("old"))),
                        "cur": ident("mac", normalize_mac(m.group("new"))),
                        "iface": m.group("iface")})
            continue
        m = _PERMANENT.search(raw)
        if m:
            out.append({"kind": "permanent_denied", "ts": when,
                        "ip": ident("ipv4", m.group("ip")),
                        "cur": ident("mac", normalize_mac(m.group("mac"))),
                        "iface": m.group("iface")})
            continue
        out.append({"kind": "unparsed", "ts": when, "raw": raw.strip()[-160:]})
    return out


def read_arp_log(seconds: float) -> List[Dict[str, Any]]:
    """최근 N초의 커널 ARP 메시지. 비root 로 읽힌다.

    `log show` 는 창 크기와 무관하게 약 1초가 든다(고정 오버헤드). 5초 주기에
    매번 넣을 수 없으므로 엔진이 빈도를 조절한다.
    """
    r = run(["log", "show", "--last", "%ds" % max(1, int(seconds)), "--style", "compact",
             "--predicate", 'process == "kernel" AND eventMessage BEGINSWITH "arp:"'],
            timeout=20)
    return parse_arp_log(r.out) if r.rc == 0 else []


def probe() -> Capability:
    r = run(["arp", "-an", "-x"], timeout=4)
    if r.not_found:
        return Capability(NAME, BROKEN, "arp 명령 없음")
    if r.rc != 0:
        return Capability(NAME, BROKEN, "arp -an -x 실패: %s" % (r.err.strip()[:60]))
    enabled = arp_logging_enabled()
    provides = ["gateway_mac", "duplicate_ip", "arp_rates"]
    hint = ""
    if enabled:
        provides.append("arp_mac_substitution")
    elif enabled is False:
        # 꺼져 있으면 MAC 치환이 카운터에도 로그에도 남지 않는다. 폴링은
        # "지금 값"만 보므로, 주기 사이에 바뀌었다 되돌아간 것은 놓친다.
        hint = msg.HINT_ARP_LOG_OFF % ARP_LOG_SYSCTL
    return Capability(NAME, OK, "%d개 이웃 항목" % len(parse_arp_table(r.out)),
                      provides=provides, hint=hint)


def collect(ctx: Dict[str, Any] = None) -> Dict[str, Any]:
    ctx = ctx or {}
    rows = parse_arp_table(run(["arp", "-an", "-x"], timeout=4).out)
    stats = parse_arp_stats(run(["netstat", "-s", "-p", "arp"], timeout=4).out)

    gw = ctx.get("gateway")
    iface = ctx.get("primary")
    gw_mac = lookup(rows, gw, iface) if gw else None

    # 같은 MAC 을 여러 IP 가 쓰는 경우를 센다. ARP 스푸핑의 전형적 흔적이지만
    # 라우터가 여러 주소를 대리 응답하는 정상 구성에서도 나온다.
    by_mac: Dict[str, List[str]] = {}
    for r in rows:
        if r["mac"] and r["iface"] == iface:
            by_mac.setdefault(r["mac"], []).append(r["ip"])
    shared = {m: ips for m, ips in by_mac.items()
              if len(ips) >= SHARED_MAC_MIN_ADDRESSES}
    top = sorted(shared.items(), key=lambda kv: -len(kv[1]))[:SHARED_MAC_MAX_ENTRIES]

    return {
        "neighbors": len([r for r in rows if r["mac"]]),
        "gateway_mac": ident("mac", gw_mac) if gw_mac else None,
        "duplicate_ip_seen": stat_like(stats, "duplicate", "ip"),
        "replies_received": stat_like(stats, "arp replies received"),
        "requests_received": stat_like(stats, "arp requests received"),
        "conflict_probe_sent": stat_like(stats, "conflict probe"),
        # 개수는 따로 남긴다. 주소 목록을 자르면서 "몇 개였는지"까지 잃으면
        # 판정이 실제보다 작은 수를 말하게 된다.
        "shared_macs": {
            m: {"count": len(ips),
                "addresses": [ident("ipv4", ip) for ip in ips[:SHARED_MAC_MAX_ADDRESSES]]}
            for m, ips in sorted(top)
        },
        "shared_mac_total": len(shared),
        "stats_keys": len(stats),
        # 커널 ARP 경고. 꺼져 있으면 MAC 치환이 어디에도 기록되지 않는다.
        "log_enabled": arp_logging_enabled(),
        # 로그 조회는 고정 1초쯤 들어 매 주기 하지 않는다. 엔진이 시킬 때만.
        **({"log_events": read_arp_log(ctx["read_arp_log"])}
           if ctx.get("read_arp_log") else {}),
    }
