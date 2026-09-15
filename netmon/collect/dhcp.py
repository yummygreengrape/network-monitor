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
    }
