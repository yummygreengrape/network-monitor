"""DNS·프록시 판정.

VPN 이나 DNS 필터를 쓰면 시스템 리졸버가 루프백이 되는 것이 정상이다.
그래서 "루프백이다"가 아니라 "루프백을 거치는 상태가 바뀌었다"를 본다.
"""
from __future__ import annotations

from typing import List, Optional

from ..model import (CONFIRMED, HIGH, INFO, MEDIUM, SECURITY, SUSPECT,
                     Finding, Observation, unwrap)

FEATURE = "detect.dns"

# 이 프록시 키가 켜지면 트래픽이 제3자를 거친다.
INTERCEPT_KEYS = ("HTTPEnable", "HTTPSEnable", "SOCKSEnable",
                  "ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable")


def _resolvers(obs: Optional[Observation]) -> List[str]:
    if obs is None:
        return []
    return [str(unwrap(r)) for r in (obs.get("dns", "resolvers") or [])]


def detect(prev: Optional[Observation], cur: Observation, ctx) -> List[Finding]:
    out: List[Finding] = []
    if prev is None:
        return out

    attribution = ctx.identity_attribution()

    p_res, c_res = _resolvers(prev), _resolvers(cur)
    if p_res and c_res and p_res != c_res:
        out.append(Finding(
            axis=SECURITY, kind="RESOLVER_CHANGED",
            confidence=CONFIRMED,
            severity="low" if attribution else HIGH,
            summary="시스템 DNS 리졸버가 바뀌었다.",
            evidence={"prev": prev.get("dns", "resolvers"), "cur": cur.get("dns", "resolvers"),
                      "source": "scutil --dns"},
            attribution=attribution,
        ))

    # 루프백 경유 상태 변화 = 로컬에서 DNS 를 가로채는 무언가가 생기거나 사라졌다.
    # VPN·필터를 켜고 끄는 정상 동작이 대부분이라 '의심'에 머문다.
    p_lb = prev.get("dns", "via_loopback")
    c_lb = cur.get("dns", "via_loopback")
    if p_lb is not None and c_lb is not None and p_lb != c_lb:
        out.append(Finding(
            axis=SECURITY, kind="DNS_LOCAL_PROXY_CHANGED",
            confidence=SUSPECT, severity=MEDIUM,
            summary=("DNS 가 로컬 프록시를 거치기 시작했다." if c_lb else
                     "DNS 가 더 이상 로컬 프록시를 거치지 않는다."),
            evidence={"prev_via_loopback": p_lb, "cur_via_loopback": c_lb,
                      "resolvers": cur.get("dns", "resolvers"), "source": "scutil --dns"},
            attribution=attribution,
        ))

    # --- 프록시 / WPAD ---
    p_proxy = prev.get("dns", "proxy") or {}
    c_proxy = cur.get("dns", "proxy") or {}
    if p_proxy != c_proxy:
        turned_on = [k for k in INTERCEPT_KEYS
                     if str(c_proxy.get(k, "0")) not in ("0", "") and str(p_proxy.get(k, "0")) in ("0", "")]
        out.append(Finding(
            axis=SECURITY,
            kind="PROXY_ENABLED" if turned_on else "PROXY_SETTINGS_CHANGED",
            confidence=CONFIRMED,
            severity=HIGH if turned_on else MEDIUM,
            summary=("프록시가 켜졌다 (%s). 트래픽이 제3자를 거친다." % ", ".join(turned_on)
                     if turned_on else "프록시 설정이 바뀌었다."),
            evidence={"prev": p_proxy, "cur": c_proxy, "source": "scutil --proxy"},
            attribution=attribution,
        ))

    return out
