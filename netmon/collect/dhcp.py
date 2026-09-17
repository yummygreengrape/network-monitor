"""DHCP 임대와 제공 옵션.

rogue DHCP 는 server_identifier / router / domain_name_server 가 바뀌는 것으로
드러난다. 임대 시작 시각은 "재접속이 있었나"를 알려주는 값이라 품질 축에서 쓴다.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..model import ident
from ..util import OK, UNSUPPORTED, Capability, run

NAME = "dhcp"


def _split_list(value: str) -> List[str]:
    """`{a, b}` 형태의 ip_mult 값을 목록으로."""
    v = value.strip()
    if v.startswith("{") and v.endswith("}"):
        v = v[1:-1]
    return [x.strip() for x in v.split(",") if x.strip()]


def parse_getpacket(text: str) -> Dict[str, Any]:
    """`ipconfig getpacket <dev>` 출력을 파싱한다.

    헤더는 `key = value`, 옵션은 `name (type): value` 형식이다.
    """
    head: Dict[str, str] = {}
    opts: Dict[str, Any] = {}
    in_opts = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("options:"):
            in_opts = True
            continue
        if not in_opts:
            if " = " in line:
                k, _, v = line.partition(" = ")
                head[k.strip()] = v.strip()
            continue
        if "(" in line and "):" in line:
            name = line.split("(", 1)[0].strip()
            typ = line.split("(", 1)[1].split(")", 1)[0].strip()
            value = line.split("):", 1)[1].strip()
            opts[name] = _split_list(value) if typ.endswith("_mult") else value
    return {"header": head, "options": opts}


# RFC 3442 option 121 (과 MS 변종 249, 그리고 구식 classful option 33).
# 이 옵션으로 밀어 넣은 경로는 VPN 기본 경로보다 구체적일 수 있어 터널을 우회한다
# — CVE-2024-3661(TunnelVision). 가정용 네트워크에서는 거의 쓰이지 않는다.
STATIC_ROUTE_OPTIONS = ("classless_static_route", "ms_classless_static_route",
                        "option_121", "option_249", "static_route", "option_33")


def _hex_bytes(value: str) -> Optional[List[int]]:
    """`0x1820c000...` 또는 `18 20 c0 00` 형태를 바이트 목록으로. 아니면 None."""
    v = value.strip().replace(" ", "").replace(":", "")
    if v.lower().startswith("0x"):
        v = v[2:]
    if not v or len(v) % 2 or any(c not in "0123456789abcdefABCDEF" for c in v):
        return None
    return [int(v[i:i + 2], 16) for i in range(0, len(v), 2)]


def decode_classless_routes(value: str) -> Optional[List[Dict[str, str]]]:
    """RFC 3442 와이어 포맷을 (목적지 프리픽스, 게이트웨이) 목록으로 푼다.

    각 항목은 [프리픽스 길이 1바이트][유효 옥텟 ceil(len/8)][게이트웨이 4바이트].
    형식을 못 알아보면 None 을 준다 — **빈 목록과 구분해야 한다.**
    옵션이 있었는데 못 읽은 것을 "정적 경로 없음"으로 보고하면 안 된다.
    """
    data = _hex_bytes(value)
    if data is None:
        return None
    out: List[Dict[str, str]] = []
    i = 0
    while i < len(data):
        plen = data[i]
        if plen > 32:
            return None
        i += 1
        need = (plen + 7) // 8
        if i + need + 4 > len(data):
            return None
        octets = data[i:i + need] + [0] * (4 - need)
        i += need
        gw = data[i:i + 4]
        i += 4
        out.append({"dest": "%s/%d" % (".".join(str(o) for o in octets), plen),
                    "gateway": ".".join(str(o) for o in gw)})
    return out


def static_routes_from(opts: Dict[str, Any]) -> Dict[str, Any]:
    """제공된 정적 경로. 옵션 유무와 해석 성공 여부를 따로 보고한다."""
    for name in STATIC_ROUTE_OPTIONS:
        if name not in opts:
            continue
        raw = opts[name]
        if isinstance(raw, list):
            raw = ",".join(raw)
        routes = decode_classless_routes(str(raw))
        if routes is None:
            # 옵션은 왔는데 형식을 못 읽었다. 없다고 말하지 않는다.
            return {"present": True, "option": name, "parsed": False, "routes": []}
        return {"present": True, "option": name, "parsed": True,
                "routes": [{"dest": ident("ipv4", r["dest"]),
                            "gateway": ident("ipv4", r["gateway"])} for r in routes]}
    # 평시(옵션 없음)에는 최소 형태만 남긴다. 주기당 바이트가 쌓이면
    # 하루 단위로는 큰 값이 된다 — 이 저장소에 shared_macs 전례가 있다.
    return {"present": False}


def parse_getsummary(text: str) -> Dict[str, str]:
    """`ipconfig getsummary <dev>` 에서 `키 : 값` 줄만 평평하게 모은다.

    중첩 블록을 무시하고 키 이름으로만 찾는다. 같은 키가 여러 번 나오면
    첫 값을 남긴다 — 자식 서비스보다 부모 서비스가 먼저 나온다.
    """
    out: Dict[str, str] = {}
    for raw in text.splitlines():
        if ":" not in raw:
            continue
        k, _, v = raw.partition(":")
        k = k.strip()
        v = v.strip()
        if not k or " " in k or not v:
            continue
        out.setdefault(k, v)
    return out


def probe() -> Capability:
    r = run(["ipconfig", "getiflist"], timeout=4)
    if r.not_found:
        return Capability(NAME, UNSUPPORTED, "ipconfig 없음")
    return Capability(NAME, OK, "ipconfig 사용 가능",
                      provides=["server_identifier", "router", "dns_offered", "lease_start"])


def collect(ctx: Dict[str, Any] = None) -> Dict[str, Any]:
    ctx = ctx or {}
    dev = ctx.get("primary")
    if not dev:
        return {"available": False, "reason": "주 인터페이스 없음"}

    pkt = parse_getpacket(run(["ipconfig", "getpacket", dev], timeout=5).out)
    summ = parse_getsummary(run(["ipconfig", "getsummary", dev], timeout=5).out)
    opts = pkt["options"]

    routers = opts.get("router") or []
    dns = opts.get("domain_name_server") or []
    if isinstance(routers, str):
        routers = [routers]
    if isinstance(dns, str):
        dns = [dns]

    return {
        "available": bool(pkt["header"] or summ),
        "server_identifier": ident("ipv4", opts["server_identifier"]) if opts.get("server_identifier") else None,
        "routers": [ident("ipv4", r) for r in routers],
        "dns_offered": [ident("ipv4", d) for d in dns],
        "subnet_mask": opts.get("subnet_mask"),
        "domain_name": opts.get("domain_name"),
        "lease_time": opts.get("lease_time"),
        "yiaddr": ident("ipv4", pkt["header"]["yiaddr"]) if pkt["header"].get("yiaddr") else None,
        "lease_start": summ.get("LeaseStartTime"),
        "lease_expire": summ.get("LeaseExpirationTime"),
        "router_arp_verified": summ.get("RouterARPVerified"),
        "state": summ.get("State"),
        "static_routes": static_routes_from(opts),
    }
