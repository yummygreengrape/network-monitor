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

from .. import messages as msg
from ..model import Finding, Observation, unwrap
from ..util import subnet_of
from . import dhcp, dns, l2, quality, route, vpn, wifi  # noqa: F401

REGISTRY = [l2, dhcp, dns, route, wifi, quality, vpn]

# 억제 사유
NETWORK_CHANGE = "network_change"
LINK_RESTART = "link_restart"
VPN_CHANGE = "vpn_change"
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
        return (self.has(NETWORK_CHANGE) or self.has(IFACE_CHANGE)
                or self.has(LINK_RESTART))

    @property
    def settling(self) -> Optional[str]:
        """흔들림 직후의 안정화 창 안인가. 그렇다면 그 사유.

        원인과 결과가 같은 주기에 떨어지지 않으므로, 창 안에서 일어난 파생
        변화는 그 흔들림으로 설명될 수 있다. **설명될 수 있다는 것이지
        무조건 억제한다는 뜻은 아니다** — 판정기가 값의 앞뒤까지 확인한다.
        """
        if self.state.get("settle_left_s"):
            return self.state.get("settle_reason")
        return None

    def quality_attribution(self) -> Optional[str]:
        """품질 판정에 붙일 억제 사유. 잠자기는 품질만 설명한다."""
        for a in (SLEEP, IFACE_CHANGE, NETWORK_CHANGE, LINK_RESTART):
            if self.has(a):
                return a
        return None

    def identity_attribution(self) -> Optional[str]:
        """네트워크 정체성이 바뀌어 설명되는 변화에만 붙는다.

        잠자기는 여기 없다. 자는 동안 붙은 AP 가 바뀌는 것이야말로
        확인해야 할 일이지 설명이 아니다.
        """
        for a in (IFACE_CHANGE, NETWORK_CHANGE, LINK_RESTART):
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


def ssid_known(obs: Observation) -> bool:
    """SSID 를 실제로 읽었는가. 위치 권한이 없으면 읽지 못한다."""
    return bool(unwrap(obs.get("wifi", "ssid")))


def link_restarted(prev: Observation, cur: Observation) -> bool:
    """링크가 한 번 끊겼다 새로 붙었는가.

    **장소를 옮겼다는 것을 알아보는 유일하게 위조하기 어려운 신호다.**
    경로에 끼어든 공격자는 내 링크를 내렸다 올리지 않는다. 그렇게 하려면
    deauth 같은 훨씬 시끄러운 짓을 해야 하고, 그것 자체가 링크 사건으로 남는다.

    셋 중 하나면 재시작으로 본다.
      기본 경로가 사라졌다 돌아옴
      Wi-Fi 링크가 끊긴 상태에서 붙음
      임대가 새로 시작되면서 **내 IP 도 바뀜** (단순 갱신은 IP 를 유지한다)
    """
    if not unwrap(prev.get("iface", "default4_gateway")) and \
            unwrap(cur.get("iface", "default4_gateway")):
        return True

    # 주 인터페이스가 잠깐 사라졌다 돌아옴
    if not prev.get("iface", "primary") and cur.get("iface", "primary"):
        return True

    p_link = (prev.get("wifi") or {}).get("link_active")
    c_link = (cur.get("wifi") or {}).get("link_active")
    if p_link and c_link and str(p_link).upper() != "TRUE" and str(c_link).upper() == "TRUE":
        return True

    p_lease, c_lease = prev.get("dhcp", "lease_start"), cur.get("dhcp", "lease_start")
    p_ip = unwrap(prev.get("dhcp", "yiaddr"))
    c_ip = unwrap(cur.get("dhcp", "yiaddr"))
    if p_lease and c_lease and p_lease != c_lease and p_ip and c_ip and p_ip != c_ip:
        return True
    return False


def _first_inet(obs: Observation) -> Optional[str]:
    for a in obs.get("iface", "primary_inet") or []:
        v = unwrap(a)
        if v:
            return str(v)
    return None


def attributions_for(prev: Optional[Observation], cur: Observation,
                     elapsed: float, interval: float,
                     anchor: Optional[Observation] = None) -> List[str]:
    """이번 주기의 변화 중 사용자 행동·환경으로 설명되는 것."""
    if prev is None:
        return [FIRST_SAMPLE]
    out: List[str] = []
    # 측정 간격이 크게 벌어짐 = 잠자기 또는 프로세스 정지
    if elapsed > interval * 3 + 10:
        out.append(SLEEP)
    # **정체성은 "주 인터페이스가 있던 마지막 관측"과 비교한다.**
    # 링크가 끊기면 기본 경로가 없어져 주 인터페이스가 None 이 되고, 다시
    # 붙으면 원래 것으로 돌아온다. 바로 앞 관측과 비교하면 정체성이 두 번
    # 뒤집히고, 그것이 iface_change 나 network_change 로 읽혀 **SSID 검사를
    # 건너뛰고 무조건 억제**하게 된다. 같은 SSID 로 다시 붙었는데 게이트웨이가
    # 바뀐 경우 — evil twin 의 모양 — 까지 덮인다. 실측에서 억제된 보안 판정
    # 22건 중 18건이 이 경로였다.
    base = anchor if (anchor is not None and anchor.get("iface", "primary")) else prev
    b_if, c_if = base.get("iface", "primary"), cur.get("iface", "primary")
    if b_if and c_if:
        if b_if != c_if:
            out.append(IFACE_CHANGE)
        elif network_key(base) != network_key(cur):
            out.append(NETWORK_CHANGE)
    # 같은 사설 대역을 쓰는 다른 장소로 옮기면 network_key 가 그대로다.
    # 192.168.0.0/24 에 게이트웨이 .1 은 세상에서 가장 흔한 조합이라, 집과
    # 카페가 같은 네트워크로 보인다. SSID 를 읽을 수 있으면 그것으로 갈리지만,
    # 위치 권한이 없으면 갈 길이 없다. 그때는 링크 재시작을 근거로 쓴다.
    if (NETWORK_CHANGE not in out and IFACE_CHANGE not in out
            and not ssid_known(cur) and link_restarted(prev, cur)):
        out.append(LINK_RESTART)

    if vpn_state_changed(prev, cur):
        out.append(VPN_CHANGE)
    return out


def vpn_state_changed(prev: Optional[Observation], cur: Observation) -> bool:
    """이번 주기에 VPN 공급자의 상태가 바뀌었는가.

    VPN 이 오르내리면 리졸버와 기본 경로가 따라 바뀐다. 그 변화를 독립된
    보안 사건으로 올리면 VPN 을 쓰는 사람에게는 끊길 때마다 high 가 두 건씩
    뜬다 — 실제로 WARP 가 49초 끊겼을 때 그렇게 났다.
    """
    if prev is None:
        return False
    p, c = prev.get("vpn") or {}, cur.get("vpn") or {}
    for name in set(p) | set(c):
        if (p.get(name) or {}).get("state") != (c.get(name) or {}).get("state"):
            return True
    return False


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
                summary=msg.DETECTOR_ERROR % (module.FEATURE, str(exc)[:120]),
                evidence={"detector": module.FEATURE, "error": repr(exc)[:200]},
            ))
    for f in findings:
        if f.network is None:
            f.network = ctx.network
    return findings
