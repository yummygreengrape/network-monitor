"""시스템 리졸버와 프록시 설정.

주의: VPN·DNS 필터를 쓰면 시스템 리졸버가 루프백(127.x)이 되는 것이 정상이다.
그 자체를 이상으로 보면 VPN 사용자 전원에게 오탐이 뜬다. 대신
"루프백을 거치는 상태가 바뀌었는가"와 "DHCP 가 준 DNS 와 어긋나는가"를 본다.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..model import ident
from ..util import OK, BROKEN, Capability, is_loopback, run

NAME = "dns"

# WPAD·프록시 자동설정은 고전적인 중간자 경로다. 이 키들의 변화를 본다.
PROXY_KEYS = (
    "HTTPEnable", "HTTPProxy", "HTTPPort",
    "HTTPSEnable", "HTTPSProxy", "HTTPSPort",
    "SOCKSEnable", "SOCKSProxy", "SOCKSPort",
    "ProxyAutoConfigEnable", "ProxyAutoConfigURLString",
    "ProxyAutoDiscoveryEnable",
)


def parse_scutil_dns(text: str) -> Dict[str, Any]:
    """`scutil --dns` 를 리졸버 목록으로.

    resolver #N 블록마다 nameserver[i], domain, search, options, if_index 를 모은다.
    """
    resolvers: List[Dict[str, Any]] = []
    cur: Optional[Dict[str, Any]] = None
    scoped = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("DNS configuration"):
            scoped = "scoped" in line
            continue
        if line.startswith("resolver #"):
            cur = {"n": line.split("#", 1)[1].strip(), "scoped": scoped,
                   "nameservers": [], "domain": None, "options": None, "if": None}
            resolvers.append(cur)
            continue
        if cur is None or ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip()
        val = val.strip()
        if key.startswith("nameserver["):
            cur["nameservers"].append(val)
        elif key == "domain":
            cur["domain"] = val
        elif key == "options":
            cur["options"] = val
        elif key == "if_index":
            cur["if"] = val.split("(", 1)[-1].rstrip(")") if "(" in val else val
    return {"resolvers": resolvers}


def parse_scutil_proxy(text: str) -> Dict[str, str]:
    """`scutil --proxy` 의 평평한 키만 뽑는다. 중첩 배열은 무시한다."""
    out: Dict[str, str] = {}
    depth = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.endswith("{"):
            depth += 1
            continue
        if line.startswith("}"):
            depth = max(0, depth - 1)
            continue
        if depth == 1 and ":" in line:
            k, _, v = line.partition(":")
            out[k.strip()] = v.strip()
    return out


def primary_resolvers(parsed: Dict[str, Any]) -> List[str]:
    """실제로 쓰이는 리졸버. mdns 같은 특수 블록은 뺀다."""
    for r in parsed.get("resolvers", []):
        opts = (r.get("options") or "")
        if r.get("nameservers") and "mdns" not in opts:
            return list(r["nameservers"])
    return []


def probe() -> Capability:
    r = run(["scutil", "--dns"], timeout=5)
    if r.not_found:
        return Capability(NAME, BROKEN, "scutil 없음")
    if r.rc != 0:
        return Capability(NAME, BROKEN, "scutil --dns 실패")
    n = len(parse_scutil_dns(r.out).get("resolvers", []))
    return Capability(NAME, OK, "리졸버 블록 %d개" % n,
                      provides=["resolvers", "proxy", "wpad"])


def collect(ctx: Dict[str, Any] = None) -> Dict[str, Any]:
    parsed = parse_scutil_dns(run(["scutil", "--dns"], timeout=5).out)
    proxy_all = parse_scutil_proxy(run(["scutil", "--proxy"], timeout=5).out)
    prim = primary_resolvers(parsed)
    return {
        "resolvers": [ident("ipv4" if "." in a else "ipv6", a) for a in prim],
        "resolver_count": len(parsed.get("resolvers", [])),
        "via_loopback": bool(prim) and all(is_loopback(a) for a in prim),
        "proxy": {k: proxy_all[k] for k in PROXY_KEYS if k in proxy_all},
        "proxy_any": any(
            proxy_all.get(k) not in (None, "0", "")
            for k in ("HTTPEnable", "HTTPSEnable", "SOCKSEnable",
                      "ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable")
        ),
    }
