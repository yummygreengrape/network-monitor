"""VPN 공급자.

사람마다 VPN 을 쓰는지조차 다르므로 기본은 꺼짐이다. 켜면 설치된 공급자를
탐침해서 있는 것만 본다.

공통 인터페이스는 좁게 둔다 — 상태, 사유, 터널 인터페이스까지다. 공급자마다
훨씬 많은 정보를 주지만, 그것을 공통 모델에 밀어 넣으면 특정 공급자의
용어가 전체 스키마를 오염시킨다.
"""
from __future__ import annotations

import re
import time

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
    # 공급자가 알려 주는 동작 모드와, 그 모드가 실제로 터널을 세우는지.
    # None 은 "모른다" 다 — 모르는 것을 보호 없음으로 적지 않는다.
    mode: Optional[str] = None
    tunnel: Optional[bool] = None

    def as_dict(self) -> Dict[str, Any]:
        return {"provider": self.provider, "state": self.state,
                "reason": self.reason, "iface": self.iface,
                "mode": self.mode, "tunnel": self.tunnel}


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


# 모드 값으로 받아들일 모양. 설정 출력의 다른 줄을 잘못 집으면 요약문에
# 엉뚱한 문자열이 실리므로, 글자와 길이를 확인한 것만 쓴다.
MODE_VALUE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,39}$")


def parse_warp_mode(text: str) -> Optional[str]:
    """`warp-cli settings` 에서 동작 모드만.

    출력은 "(user set)\tMode: DnsOverTls" 처럼 앞에 출처 표시가 붙고,
    "WARP tunnel protocol: MASQUE" 처럼 mode 가 아닌 줄도 있다. 키가 정확히
    `mode` 인 줄만 받는다 — 제외 목록은 줄이 하나 늘면 조용히 무너진다.
    """
    for line in (text or "").splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        # 앞의 "(user set)" 같은 출처 표시를 떼고 키만 본다.
        key = key.split(")")[-1].strip().lower()
        if key != "mode":
            continue
        value = value.strip()
        return value if MODE_VALUE_RE.match(value) else None
    return None


def warp_tunnel_for(mode: Optional[str]) -> Optional[bool]:
    """모드 이름이 터널을 세우는 모드인가.

    **"연결됨" 이 "보호받는 중" 을 뜻하지 않는다.** DNS only 모드(DnsOverTls,
    DnsOverHttps)에서도 warp-cli 는 `Status update: Connected` 를 돌려준다.
    2026-09-21 실측에서 이 때문에 터널이 없는데도 연결로 기록됐고, 보호가
    사라진 사실이 판정에 한 번도 잡히지 않았다.
    """
    if not mode:
        return None
    low = mode.strip().lower()
    if low.startswith("dnsover"):
        return False
    if "warp" in low:
        return True
    return None


class Warp(Provider):
    name, cmd = "warp", "warp-cli"
    # 모드는 사람이 바꿀 때만 바뀐다. 주기마다 명령을 하나 더 띄우지 않는다
    # (ARP 로그·Wi-Fi 헬퍼도 같은 방식으로 간격을 둔다).
    MODE_EVERY_SECONDS = 60.0
    # 못 읽은 채 이만큼 지나면 옛 값을 버린다. 모르는 것과 잠깐 못 읽은 것은
    # 다르지만, "잠깐" 이 길어지면 옛 모드를 이번 관측처럼 싣게 된다.
    MODE_MAX_AGE_SECONDS = 300.0
    _mode_cache: Optional[str] = None
    _mode_read_at: Optional[float] = None

    def mode(self, now: Optional[float] = None) -> Optional[str]:
        now = time.time() if now is None else now
        # **읽은 적 없음과 읽었는데 해석 못 함은 다르다.** 시각으로만 가드하지
        # 않으면, 출력 형식이 바뀌어 해석에 실패하는 동안(기능이 조용히 꺼진 바로
        # 그 상태) 주기마다 명령을 다시 띄운다.
        if self._mode_read_at is not None and now - self._mode_read_at < self.MODE_EVERY_SECONDS:
            return self._mode_cache
        r = run([self.path() or self.cmd, "settings"], timeout=6)
        if not r.ok:
            # 일시적 실패는 다음 주기에 다시 시도한다. 너무 오래된 값은 버린다.
            if (self._mode_read_at is not None
                    and now - self._mode_read_at <= self.MODE_MAX_AGE_SECONDS):
                return self._mode_cache
            self._mode_cache = None
            return None
        self._mode_cache, self._mode_read_at = parse_warp_mode(r.out), now
        return self._mode_cache

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
        mode = self.mode() if state == CONNECTED else None
        return VpnStatus(self.name, state, reason=reason, raw=first_line(text),
                         mode=mode, tunnel=warp_tunnel_for(mode))


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
