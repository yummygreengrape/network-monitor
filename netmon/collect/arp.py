"""ARP 이웃 표와 ARP 통계.

게이트웨이 MAC 변경과 IP 충돌이 여기서 나온다. 통계 카운터의 증가분도
함께 본다 — ARP 응답 수가 갑자기 뛰면 스푸핑 시도의 흔적일 수 있다.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

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


def probe() -> Capability:
    r = run(["arp", "-an", "-x"], timeout=4)
    if r.not_found:
        return Capability(NAME, BROKEN, "arp 명령 없음")
    if r.rc != 0:
        return Capability(NAME, BROKEN, "arp -an -x 실패: %s" % (r.err.strip()[:60]))
    return Capability(NAME, OK, "%d개 이웃 항목" % len(parse_arp_table(r.out)),
                      provides=["gateway_mac", "duplicate_ip", "arp_rates"])


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
    }
