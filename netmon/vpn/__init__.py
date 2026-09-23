"""VPN 공급자.

사람마다 VPN 을 쓰는지조차 다르므로 기본은 꺼짐이다. 켜면 설치된 공급자를
탐침해서 있는 것만 본다.

공통 인터페이스는 좁게 둔다 — 상태, 사유, 터널 인터페이스까지다. 공급자마다
훨씬 많은 정보를 주지만, 그것을 공통 모델에 밀어 넣으면 특정 공급자의
용어가 전체 스키마를 오염시킨다.
"""
from __future__ import annotations

import ipaddress
import re
import time

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

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

    **"연결됨" 이 "터널이 있음" 을 뜻하지 않는다.** DNS only 모드(DnsOverTls,
    DnsOverHttps)에서도 warp-cli 는 `Status update: Connected` 를 돌려준다.
    2026-09-21 실측에서 이 때문에 터널이 없는데도 연결로 기록됐고, 터널의
    보호가 사라진 사실이 판정에 한 번도 잡히지 않았다.
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
                # **"disconnected" 에도 "connect" 가 들어 있다.** 부분 문자열로
                # 먼저 가르면 `Disconnected` 가 connecting 으로 기록된다.
                # 기록에서 그 흔적으로 보이는 것과 근거의 한계는
                # tests/test_detect_vpn.py 의 TestWarpStatusParsing 에 적었다.
                # `Unable`(No Network 등)은 전과 같이 끊김이다.
                state = (CONNECTED if low.startswith("connected")
                         else DISCONNECTED if low.startswith("disconnected")
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


# --- 터널 엔드포인트 ---
#
# 공급자가 끊김 사유에 상대편 주소를 적어 주는 판이 있다
# (예: "No Network via 198.51.100.7:2408"). 그 주소를 재면 로컬 구간과 터널
# 상대편 구간을 나눌 근거가 생긴다 — 지금은 상대편 관측값이 0건이라 비교
# 대상이 없다.
#
# **대상 주소를 우리가 정하지 않는다.** 사유 문자열을 만드는 쪽이 정한다.
# 그래서 주소는 하나만 고르고, 공인 유니캐스트가 아니면 버린다
# (_work/redteam.md "공격자가 정할 수 있는 값"). 고르지 못하면 관측하지
# 않는다 — 없는 대상에 보내는 것보다 재지 않는 편이 낫다.

# 보내는 상태는 둘뿐이다. **`unknown` 은 제외한다** — `unknown` 은 공급자
# 조회가 실패했을 때의 상태이고 그때의 사유는 stderr 문자열이라(위 `status`
# 들의 `reason=(r.err or ...)`), 거기 섞인 주소는 터널 상대편이 아니다.
# 끝나는 조건도 없어서, 설치만 하고 꺼 둔 공급자나 조회가 계속 실패하는
# 공급자가 있으면 무한히 나간다 (AC-4 수정분, 사용자 확인 2026-09-22).
PROBE_STATES = (DISCONNECTED, CONNECTING)

# **한 공급자의 한 끊김**에 엔드포인트로 보낼 최대 ICMP 발 수.
# 주기가 아니라 발 수를 센다 — 한 주기에 나가는 발 수는 `ping_count` 설정에
# 달렸고(netmon/collect/link.py 의 `per = 1 if n > 1 else count`), 주기를 세면
# 그 설정을 올려 둔 사람에게는 12발보다 많이 나간다 (AC-4 수정분은 "발").
#
# 기본값(ping_count=1)에서 12주기치이고, 실제 시간은 주기 설정에 달렸다 —
# 기본 5초 주기면 약 1분, 조사 중 좁혀진 2~3초 주기면 24~36초다. 원인 판별에
# 필요한 것은 끊김 초반이고, 67분짜리 끊김에서 수백 발이 제3자에게 나가는
# 일을 막는다 (AC-4 수정분).
TUNNEL_PROBE_CAP = 12

# 그 발 수를 담는 `state.json` 의 키. 모양은 `carry_probe_counts` 가 만드는
# `{공급자: {"shots": 발 수, "capped": 상한에 닿았는가}}` 다.
#
# **쓰는 쪽과 읽는 쪽이 갈라지지 않게 여기 한 곳에 둔다.** 쓰는 것은 엔진
# (netmon/engine.py)이고 읽는 것은 복구 판정(netmon/detect/vpn.py)인데, 읽는
# 쪽이 문자열 리터럴을 따로 적고 있었다. 그러면 이름을 바꿀 때 테스트가 전부
# 통과한 채 복구 증거의 `tunnel_endpoint_shots`·`tunnel_endpoint_cap_reached`
# 두 필드만 조용히 사라진다. 엔진이 detect 를 부르므로 그 반대 방향으로는
# 상수를 둘 수 없어(순환 import) 수집기 쪽인 이 파일에 둔다.
#
# **없어도 동작한다** — 키가 없거나 모양이 다르면 0 부터 센다.
ENDPOINT_PROBES_KEY = "vpn_endpoint_probes"

# 사유 문자열에서 훑을 최대 길이. 긴 문자열에 시간을 쓰지 않는다.
REASON_SCAN_LIMIT = 512

# 훑어볼 최대 후보 수. 숫자 덩어리가 늘어서 있어도 앞쪽만 본다.
REASON_MAX_CANDIDATES = 8

# 점 넷으로 이어진 숫자. 앞뒤가 다른 주소의 일부이면(`198.51.100.7.9`,
# `::ffff:198.51.100.7`) 고르지 않는다 — 잘린 조각을 주소로 적지 않으려는
# 것이다. 유효성은 정규식이 아니라 ipaddress 가 판정한다.
_IPV4_IN_TEXT = re.compile(r"(?<![0-9A-Za-z.:])(\d{1,3}(?:\.\d{1,3}){3})(?![0-9A-Za-z.])")

# 보내지 않는 대역. **표준 라이브러리의 `is_global` 을 쓰지 않는다** — 그쪽은
# 문서용 대역(192.0.2.0/24·198.51.100.0/24·203.0.113.0/24)도 사설로 보는데,
# 이 저장소의 테스트는 그 대역만 쓸 수 있어(공개 저장소라 실제 주소를 넣지
# 않는다) 이 갈래를 시험할 주소가 남지 않는다. 그래서 명세가 열거한 대역을
# 그대로 적는다. 240.0.0.0/4 에 255.255.255.255 가 들어간다.
BLOCKED_V4 = (
    "0.0.0.0/8",        # 이 네트워크·미지정
    "10.0.0.0/8",       # 사설
    "100.64.0.0/10",    # CGNAT
    "127.0.0.0/8",      # 루프백
    "169.254.0.0/16",   # 링크로컬
    "172.16.0.0/12",    # 사설
    "192.168.0.0/16",   # 사설
    "224.0.0.0/4",      # 멀티캐스트
    "240.0.0.0/4",      # 예약 + 브로드캐스트
)

_BLOCKED_NETS = tuple(ipaddress.IPv4Network(n) for n in BLOCKED_V4)


def public_unicast(addr: Any) -> bool:
    """이 주소로 보내도 되는가. IPv4 공인 유니캐스트만 참이다.

    IPv6 는 이번 범위에서 대상으로 삼지 않으므로(AC-4b) 거짓이다.
    해석되지 않는 문자열도 거짓이다 — 모르는 것에 보내지 않는다.
    """
    try:
        ip = ipaddress.IPv4Address(str(addr).strip())
    except (ipaddress.AddressValueError, ValueError):
        return False
    return not any(ip in net for net in _BLOCKED_NETS)


def endpoint_from_reason(reason: Any) -> Optional[str]:
    """공급자 사유 문자열에서 잴 만한 엔드포인트 주소 하나.

    - IPv4 만 고르고 포트는 버린다. IPv6 만 있으면 고르지 않는다 (AC-4b).
    - 숫자 모양이지만 주소가 아닌 것(`999.1.2.3`)은 건너뛰고 다음 후보를 본다.
      **잘못된 조각을 주소로 기록하지 않는다.**
    - 고른 주소가 공인 유니캐스트가 아니면 거기서 멈춘다(다음 후보로 넘어가지
      않는다). 사설 주소 뒤에 공인 주소를 붙여 대상을 고르게 하는 문자열이
      성공하지 않게 한다.
    - 제어문자·이스케이프·개행이 섞여 있어도 예외 없이 끝난다. 돌려주는 값은
      `ipaddress` 가 해석한 주소 문자열뿐이라 그런 문자가 실려 나가지 않는다.
    """
    if not isinstance(reason, str) or not reason:
        return None
    text = reason[:REASON_SCAN_LIMIT]
    for i, m in enumerate(_IPV4_IN_TEXT.finditer(text)):
        if i >= REASON_MAX_CANDIDATES:
            return None
        try:
            ip = ipaddress.IPv4Address(m.group(1))
        except (ipaddress.AddressValueError, ValueError):
            continue  # 주소 모양의 다른 숫자다. 다음 후보를 본다.
        return str(ip) if public_unicast(ip) else None
    return None


def carry_probe_counts(raw: Any,
                       vpn_block: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """직전 주기까지의 발 수 기록을 이번 주기로 이어 준다.

    모양은 `{공급자: {"shots": 발 수, "capped": 상한에 닿았는가}}` 이고,
    엔진이 `state.json` 의 `vpn_endpoint_probes` 에 그대로 담는다.

    **세는 단위는 공급자 하나의 끊김 하나다.** 창은 그 공급자의 상태로만
    열고 닫는다.

    - `PROBE_STATES`(disconnected·connecting): 창이 이어진다. 기록을 그대로 둔다.
    - `CONNECTED`: 그 공급자의 끊김이 끝났다. 기록을 버리고 다음 끊김을 0 부터 센다.
    - `UNKNOWN`: **이미 있는 기록만 유지하고, 없는 것을 만들지 않는다.** 그 상태는
      "공급자에게 물어보지 못했다" 이지 "끊겼다" 도 "이어졌다" 도 아니다. 닫는
      것으로 보면 조회가 간헐적으로 실패하는 동안 상한이 계속 되살아나 한 끊김에
      12발보다 많이 나간다. 여는 것으로 보면 `MacOSNative` 처럼 담당할 서비스가
      없어 **늘 `unknown` 을 돌려주는 공급자**(이 파일 `status()` 의 "직접 담당할
      서비스 없음")가 창을 영영 열어 둬, 상한이 한 끊김이 아니라 프로세스 수명당
      예산이 된다. 여기서는 보내지 않으므로(`PROBE_STATES` 에 없다) 기록이 새로
      생길 일도 없다.
    - 블록에 없는 공급자(설정 변경, 수집 실패로 블록이 통째로 빈 주기): 기록을
      유지한다. 관측하지 못한 것을 "연결됐다" 로 읽지 않는다.

    값이 없거나 모양이 다르면(옛 판의 정수 하나, 문자열, None) 아무것도 이어
    주지 않는다 — 기록이 없는 것과 같이 0 부터 센다.
    """
    out: Dict[str, Dict[str, Any]] = {}
    if not isinstance(raw, dict):
        return out
    states = vpn_block if isinstance(vpn_block, dict) else {}
    for name, rec in raw.items():
        if not isinstance(name, str) or not isinstance(rec, dict):
            continue
        shots = rec.get("shots")
        if not isinstance(shots, int) or isinstance(shots, bool) or shots < 0:
            continue
        st = states.get(name)
        if isinstance(st, dict) and st.get("state") == CONNECTED:
            continue
        out[name] = {"shots": shots, "capped": bool(rec.get("capped"))}
    return out


def tunnel_endpoint(vpn_block: Optional[Dict[str, Any]]) -> Optional[str]:
    """**직전 주기**의 VPN 관측에서, 이번 주기에 재 볼 엔드포인트 주소.

    `disconnected` 와 `connecting` 인 공급자만 본다 (`PROBE_STATES`).
    연결돼 있는 공급자를 보지 않는 것은 평소 주기에 아무것도 보내지 않기
    위해서고, `unknown` 을 보지 않는 것은 그때의 사유가 공급자가 말해 준
    끊김 사유가 아니기 때문이다 (AC-4 수정분). 그래서 연결이 끊긴 첫
    주기에는 (직전 주기가 connected 라) 주소가 없고, 관측은 한 주기 늦게
    시작된다 (AC-4c).

    공급자가 여럿이면 이름 순으로 첫 번째를 고른다. 대상은 한 주기에 하나다.

    주소만 필요할 때 쓴다. 상한은 공급자별로 세므로 엔진은 어느 공급자에게서
    나온 주소인지도 알아야 한다 — 그쪽은 `tunnel_probe_target` 이다.
    """
    target = tunnel_probe_target(vpn_block)
    return target[1] if target else None


def tunnel_probe_target(
        vpn_block: Optional[Dict[str, Any]]) -> Optional[Tuple[str, str]]:
    """(주소를 내준 공급자 이름, 엔드포인트 주소). 고르지 못하면 None.

    상한(`TUNNEL_PROBE_CAP`)을 그 공급자 앞으로 달아야 하므로 이름을 함께
    돌려준다. 고르는 규칙은 `tunnel_endpoint` 의 설명과 같다.
    """
    if not isinstance(vpn_block, dict):
        return None
    for name in sorted(vpn_block):
        st = vpn_block.get(name)
        if not isinstance(st, dict) or st.get("state") not in PROBE_STATES:
            continue
        addr = endpoint_from_reason(st.get("reason"))
        if addr:
            return str(name), addr
    return None
