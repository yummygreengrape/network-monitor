"""판정.

규칙 두 가지가 이 계층 전체를 지배한다.

1. **축을 나눈다.** 하나의 관측이 품질 판정과 보안 판정을 동시에 낼 수 있다.
   원인을 하나만 고르면 품질 사건이 보안 사건을 가린다. 원래 스크립트에서
   `NETWORK_CHANGE` 가 `ARP_ANOMALY` 보다 먼저 판정돼서, 네트워크가 바뀌는
   동시에 게이트웨이 MAC 이 바뀌는 경우 — evil twin 으로 유인당하는 바로
   그 순간 — ARP 이상이 기록되지 않았다.

2. **억제는 덮어쓰기가 아니라 꼬리표다.** 사용자 행동으로 설명되는 변화에는
   `attribution` 이 붙지만 판정 자체는 그대로 기록된다. 나중에 다시 볼 수 있다.

네트워크 정체성(network_key)에는 게이트웨이 MAC 과 BSSID 를 **넣지 않는다.**
그 둘이 우리가 감시하는 대상이기 때문이다. 정체성에 넣으면 MAC 이 바뀔 때마다
"다른 네트워크로 옮겼다"가 되어 스스로 경보를 지운다.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..model import Finding, Observation, unwrap
from ..util import subnet_of
from . import dhcp, dns, l2, quality, route, wifi  # noqa: F401

REGISTRY = [l2, dhcp, dns, route, wifi, quality]

# 억제 사유
NETWORK_CHANGE = "network_change"
SLEEP = "sleep"
IFACE_CHANGE = "iface_change"
FIRST_SAMPLE = "first_sample"


@dataclass
class Context:
    """판정 한 번에 필요한 주변 정보. 순수 자료다 — 명령을 실행하지 않는다."""

    elapsed: float = 0.0
    interval: float = 5.0
    features: Dict[str, bool] = field(default_factory=dict)
    state: Dict[str, Any] = field(default_factory=dict)
    attributions: List[str] = field(default_factory=list)
    network: Optional[str] = None

    def enabled(self, feature: str) -> bool:
        return bool(self.features.get(feature, True))

    def has(self, attribution: str) -> bool:
        return attribution in self.attributions

    @property
    def moved(self) -> bool:
        return self.has(NETWORK_CHANGE) or self.has(IFACE_CHANGE)

    def quality_attribution(self) -> Optional[str]:
        """품질 판정에 붙일 억제 사유. 잠자기는 품질만 설명한다."""
        for a in (SLEEP, IFACE_CHANGE, NETWORK_CHANGE):
            if self.has(a):
                return a
        return None

    def identity_attribution(self) -> Optional[str]:
        """네트워크 정체성이 바뀌어 설명되는 변화에만 붙는다.

        잠자기는 여기 없다. 자는 동안 붙은 AP 가 바뀌는 것이야말로
        확인해야 할 일이지 설명이 아니다.
        """
        for a in (IFACE_CHANGE, NETWORK_CHANGE):
            if self.has(a):
                return a
        return None


def network_key(obs: Observation) -> str:
    """네트워크 정체성. 이것이 바뀌면 다른 네트워크로 옮긴 것이다.

    **우리가 감시하는 값은 여기 들어가지 않는다.** 게이트웨이 MAC, BSSID,
    DHCP 서버, 게이트웨이 IP 는 전부 공격자가 바꿀 수 있는 값이고, 정체성에
    넣으면 공격이 스스로 "네트워크가 바뀌었다"를 만들어 자기 경보를 지운다.
    rogue DHCP 판정을 쓰면서 실제로 이 실수를 했다 (tests/test_detect.py).

    남는 것은 세 가지다.
      인터페이스   Wi-Fi 에서 유선으로 옮기면 다른 경로다
      SSID         위치 권한이 있을 때만. 다른 네트워크의 가장 강한 증거다
      서브넷       다른 대역을 받았으면 옮긴 것이다. 같은 대역을 유지하는
                   것이 rogue DHCP 의 조건이므로 공격에 악용되기 어렵다
    """
    addr = unwrap(obs.get("dhcp", "yiaddr")) or _first_inet(obs)
    mask = obs.get("dhcp", "subnet_mask") or obs.get("iface", "primary_netmask")
    parts = [
        str(obs.get("iface", "primary") or "-"),
        str(unwrap(obs.get("wifi", "ssid")) or "-"),
        str(subnet_of(str(addr) if addr else None, mask) or "-"),
    ]
    return "|".join(parts)


def _first_inet(obs: Observation) -> Optional[str]:
    for a in obs.get("iface", "primary_inet") or []:
        v = unwrap(a)
        if v:
            return str(v)
    return None


def attributions_for(prev: Optional[Observation], cur: Observation,
                     elapsed: float, interval: float) -> List[str]:
    """이번 주기의 변화 중 사용자 행동·환경으로 설명되는 것."""
    if prev is None:
        return [FIRST_SAMPLE]
    out: List[str] = []
    # 측정 간격이 크게 벌어짐 = 잠자기 또는 프로세스 정지
    if elapsed > interval * 3 + 10:
        out.append(SLEEP)
    if prev.get("iface", "primary") != cur.get("iface", "primary"):
        out.append(IFACE_CHANGE)
    elif network_key(prev) != network_key(cur):
        out.append(NETWORK_CHANGE)
    return out


def run_all(prev: Optional[Observation], cur: Observation, ctx: Context) -> List[Finding]:
    findings: List[Finding] = []
    for module in REGISTRY:
        if not ctx.enabled(module.FEATURE):
            continue
        try:
            findings.extend(module.detect(prev, cur, ctx) or [])
        except Exception as exc:  # 한 판정기의 버그가 나머지를 막지 않는다
            findings.append(Finding(
                axis="info", kind="DETECTOR_ERROR", confidence="confirmed", severity="low",
                summary="판정기 %s 가 예외로 멈춤: %s" % (module.FEATURE, str(exc)[:120]),
                evidence={"detector": module.FEATURE, "error": repr(exc)[:200]},
            ))
    for f in findings:
        if f.network is None:
            f.network = ctx.network
    return findings
