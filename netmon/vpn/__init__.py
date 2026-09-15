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

from ..util import OK, UNSUPPORTED, Capability, first_line, have, run

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

    def installed(self) -> bool:
        return have(self.cmd)

    def probe(self) -> Capability:
        if not self.installed():
            return Capability("vpn." + self.name, UNSUPPORTED, "%s 설치되지 않음" % self.cmd)
        return Capability("vpn." + self.name, OK, "%s 사용 가능" % self.cmd, provides=["vpn_state"])

    def status(self) -> VpnStatus:
        raise NotImplementedError


class Warp(Provider):
    name, cmd = "warp", "warp-cli"

    def status(self) -> VpnStatus:
        r = run([self.cmd, "status"], timeout=6)
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
        r = run([self.cmd, "status", "--json"], timeout=8)
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
        r = run([self.cmd, "show", "interfaces"], timeout=6)
        if not r.ok:
            return VpnStatus(self.name, UNKNOWN, reason="wg show 실패(권한 필요할 수 있음)")
        ifaces = r.out.split()
        return VpnStatus(self.name, CONNECTED if ifaces else DISCONNECTED,
                         iface=ifaces[0] if ifaces else None)


class MacOSNative(Provider):
    """시스템 설정에 등록된 VPN 서비스 (IKEv2 / IPsec / L2TP)."""

    name, cmd = "macos", "scutil"

    def status(self) -> VpnStatus:
        r = run([self.cmd, "--nc", "list"], timeout=6)
        if not r.ok:
            return VpnStatus(self.name, UNKNOWN, reason="scutil --nc list 실패")
        connected = [l for l in r.out.splitlines() if "(Connected)" in l]
        configured = [l for l in r.out.splitlines() if l.strip().startswith("*")]
        if not configured:
            return VpnStatus(self.name, UNKNOWN, reason="등록된 VPN 서비스 없음")
        return VpnStatus(self.name, CONNECTED if connected else DISCONNECTED,
                         reason="%d개 등록" % len(configured))


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
