"""VPN 공급자.

사람마다 VPN 을 쓰는지조차 다르므로 기본은 꺼짐이다. 켜면 설치된 공급자를
탐침해서 있는 것만 본다.

공통 인터페이스는 좁게 둔다 — 상태, 사유, 터널 인터페이스까지다. 공급자마다
훨씬 많은 정보를 주지만, 그것을 공통 모델에 밀어 넣으면 특정 공급자의
용어가 전체 스키마를 오염시킨다.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ..util import OK, UNSUPPORTED, Capability, find_tool, first_line, have, run

# 공통 상태
CONNECTED = "connected"
DISCONNECTED = "disconnected"
CONNECTING = "connecting"
UNKNOWN = "unknown"


@dataclass
class VpnStatus:
    provider: str
    state: str
    reason: Optional[str] = None
    iface: Optional[str] = None
    raw: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return {"provider": self.provider, "state": self.state,
                "reason": self.reason, "iface": self.iface}


class Provider:
    name = "?"
    cmd = "?"

    def path(self) -> Optional[str]:
        """실행 파일의 절대 경로. PATH 에 기대지 않는다."""
        return find_tool(self.cmd)

    def installed(self) -> bool:
        return self.path() is not None

    def probe(self) -> Capability:
        if not self.installed():
            return Capability("vpn." + self.name, UNSUPPORTED, "%s 설치되지 않음" % self.cmd)
        return Capability("vpn." + self.name, OK, "%s" % self.path(), provides=["vpn_state"])

    def status(self) -> VpnStatus:
        raise NotImplementedError


class Warp(Provider):
    name, cmd = "warp", "warp-cli"

    def status(self) -> VpnStatus:
        r = run([self.path() or self.cmd, "status"], timeout=6)
        if not r.ok:
            return VpnStatus(self.name, UNKNOWN, reason=(r.err or "조회 실패")[:80])
        text = r.out
        state, reason = UNKNOWN, None
        for line in text.splitlines():
            line = line.strip()
            if line.lower().startswith("status update:"):
                val = line.split(":", 1)[1].strip()
                low = val.lower()
                state = (CONNECTED if low.startswith("connected")
                         else CONNECTING if "connect" in low
                         else DISCONNECTED)
            elif line.lower().startswith("reason:"):
                reason = line.split(":", 1)[1].strip()
        return VpnStatus(self.name, state, reason=reason, raw=first_line(text))


class Tailscale(Provider):
    name, cmd = "tailscale", "tailscale"

    def status(self) -> VpnStatus:
        r = run([self.path() or self.cmd, "status", "--json"], timeout=8)
        if not r.ok:
            return VpnStatus(self.name, UNKNOWN, reason=(r.err or "조회 실패")[:80])
        import json
        try:
            d = json.loads(r.out)
        except ValueError:
            return VpnStatus(self.name, UNKNOWN, reason="JSON 파싱 실패")
        backend = str(d.get("BackendState", "")).lower()
        state = (CONNECTED if backend == "running"
                 else CONNECTING if backend in ("starting", "needslogin")
                 else DISCONNECTED if backend == "stopped" else UNKNOWN)
        return VpnStatus(self.name, state, reason=d.get("BackendState"))


class WireGuard(Provider):
    name, cmd = "wireguard", "wg"

    def status(self) -> VpnStatus:
        r = run([self.path() or self.cmd, "show", "interfaces"], timeout=6)
        if not r.ok:
            return VpnStatus(self.name, UNKNOWN, reason="wg show 실패(권한 필요할 수 있음)")
        ifaces = r.out.split()
        return VpnStatus(self.name, CONNECTED if ifaces else DISCONNECTED,
                         iface=ifaces[0] if ifaces else None)


# 서드파티 VPN 앱은 시스템에 NetworkExtension 을 등록해서 `scutil --nc list`
# 에도 나타난다. 전용 공급자가 이미 보고 있는 것을 여기서 또 세면 같은 VPN 이
# 두 번 집계된다. 실측에서 Tailscale 이 그렇게 중복됐다.
HANDLED_BUNDLES = {
    "io.tailscale.ipn.macsys": "tailscale",
    "com.cloudflare.1dot1dot1dot1.macos": "warp",
    "com.cloudflare.cloudflareone.macos": "warp",
}


def parse_nc_list(text: str) -> List[Dict[str, Any]]:
    """`scutil --nc list` 를 서비스 목록으로. 순수 함수.

    줄 형식:
      * (Connected)  <UUID> VPN (<번들 id>) "<이름>"  [VPN:<번들 id>]

    따옴표 안의 이름은 사용자가 지은 것이라 소속을 드러낼 수 있다. **읽지 않는다.**
    """
    import re

    out: List[Dict[str, Any]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("Available network"):
            continue
        state_m = re.search(r"\(([A-Za-z ]+)\)", line)
        tag_m = re.search(r"\[([^\]]+)\]\s*$", line)
        if not state_m or not tag_m:
            continue
        tag = tag_m.group(1)
        bundle = tag.split(":", 1)[1] if ":" in tag else tag
        out.append({
            "enabled": line.startswith("*"),
            "state": state_m.group(1).strip().lower(),
            "kind": tag.split(":", 1)[0],
            "bundle": bundle,
        })
    return out


class MacOSNative(Provider):
    """시스템 설정에 등록된 VPN 서비스 (IKEv2 / IPsec / L2TP).

    전용 공급자가 따로 있는 서드파티 확장은 제외한다.
    """

    name, cmd = "macos", "scutil"

    def status(self) -> VpnStatus:
        r = run([self.path() or self.cmd, "--nc", "list"], timeout=6)
        if not r.ok:
            return VpnStatus(self.name, UNKNOWN, reason="scutil --nc list 실패")
        services = [s for s in parse_nc_list(r.out)
                    if s["bundle"] not in HANDLED_BUNDLES]
        if not services:
            return VpnStatus(self.name, UNKNOWN,
                             reason="직접 담당할 서비스 없음 (전용 공급자가 처리)")
        enabled = [s for s in services if s["enabled"]]
        if not enabled:
            return VpnStatus(self.name, DISCONNECTED,
                             reason="%d개 등록, 사용 안 함" % len(services))
        connected = [s for s in enabled if s["state"] == "connected"]
        return VpnStatus(self.name, CONNECTED if connected else DISCONNECTED,
                         reason="%d개 사용 중" % len(enabled))


ALL: List[Provider] = [Warp(), Tailscale(), WireGuard(), MacOSNative()]


def installed_providers() -> List[Provider]:
    return [p for p in ALL if p.installed()]


def resolve(names: List[str]) -> List[Provider]:
    if not names or "auto" in names:
        return installed_providers()
    want = set(names)
    return [p for p in ALL if p.name in want and p.installed()]


def collect(providers: List[Provider]) -> Dict[str, Any]:
    return {p.name: p.status().as_dict() for p in providers}


def probe_all() -> List[Capability]:
    return [p.probe() for p in ALL]
