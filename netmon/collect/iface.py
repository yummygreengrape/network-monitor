"""인터페이스 열거와 기본 경로.

여기서 물리 경로와 터널 경로를 나눈다. VPN 이 켜져 있으면 기본 경로를
utun 이 쥐고 있어서, 기본 경로 인터페이스를 그대로 "내 Wi-Fi"로 쓰면
게이트웨이도 MAC 도 DHCP 도 전부 엉뚱한 것을 보게 된다.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..model import ident
from ..util import OK, Capability, run

NAME = "iface"

# 터널·가상 인터페이스 접두사. 물리 경로를 찾을 때 건너뛴다.
TUNNEL_PREFIXES = ("utun", "ipsec", "ppp", "tun", "tap", "gif", "stf", "ppoe")
# 물리지만 기본 경로를 담당하지 않는 것들
SKIP_PREFIXES = ("awdl", "llw", "bridge", "ap", "lo", "gpd", "anpi")


def is_tunnel(dev: str) -> bool:
    return dev.startswith(TUNNEL_PREFIXES)


def port_kind(port_name: str) -> str:
    """하드웨어 포트 이름으로 종류를 정한다. Wi-Fi 탐지를 적용할지 가른다."""
    p = port_name.lower()
    if "wi-fi" in p or "airport" in p:
        return "wifi"
    if "ethernet" in p or "lan" in p:
        return "ethernet"
    if "thunderbolt" in p or "usb" in p:
        return "ethernet"
    if "bluetooth" in p:
        return "bluetooth"
    if "iphone" in p or "ipad" in p:
        return "tether"
    return "other"


def parse_hardware_ports(text: str) -> List[Dict[str, str]]:
    """`networksetup -listallhardwareports` 출력을 파싱한다."""
    ports: List[Dict[str, str]] = []
    cur: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("Hardware Port:"):
            if cur.get("dev"):
                ports.append(cur)
            cur = {"port": line.split(":", 1)[1].strip()}
        elif line.startswith("Device:") and cur:
            cur["dev"] = line.split(":", 1)[1].strip()
    if cur.get("dev"):
        ports.append(cur)
    for p in ports:
        p["kind"] = port_kind(p.get("port", ""))
    return ports


def parse_route_get(text: str) -> Dict[str, Optional[str]]:
    """`route -n get [-ifscope X] default` 출력에서 필요한 값만."""
    out: Dict[str, Optional[str]] = {"gateway": None, "interface": None, "destination": None}
    for line in text.splitlines():
        line = line.strip()
        for key in ("gateway", "interface", "destination"):
            if line.startswith(key + ":"):
                out[key] = line.split(":", 1)[1].strip()
    return out


def parse_ifconfig(text: str) -> Dict[str, Any]:
    """`ifconfig <dev>` 에서 상태·주소·하드웨어 주소."""
    out: Dict[str, Any] = {"status": None, "ether": None, "inet": [], "inet6": [], "flags_up": False}
    for raw in text.splitlines():
        line = raw.strip()
        if raw and not raw[0].isspace() and "flags=" in raw:
            out["flags_up"] = "UP" in raw.split("flags=", 1)[1].split(">", 1)[0]
        if line.startswith("status:"):
            out["status"] = line.split(":", 1)[1].strip()
        elif line.startswith("ether "):
            out["ether"] = line.split(None, 1)[1].strip()
        elif line.startswith("inet "):
            parts = line.split()
            addr = parts[1]
            netmask = None
            if "netmask" in parts:
                netmask = parts[parts.index("netmask") + 1]
            out["inet"].append({"addr": addr, "netmask": netmask})
        elif line.startswith("inet6 "):
            addr = line.split()[1].split("%", 1)[0]
            out["inet6"].append({"addr": addr})
    return out


def parse_service_order(text: str) -> List[str]:
    """`networksetup -listnetworkserviceorder` 에서 우선순위대로 device 이름."""
    devs: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("(Hardware Port:") and "Device:" in line:
            seg = line.split("Device:", 1)[1]
            dev = seg.split(")", 1)[0].strip().rstrip(",")
            if dev:
                devs.append(dev)
    return devs


def choose_primary(
    ports: List[Dict[str, str]],
    order: List[str],
    if_state: Dict[str, Dict[str, Any]],
    default4_iface: Optional[str],
) -> Optional[str]:
    """물리 주 인터페이스를 고른다.

    기본 경로가 터널이 아니면 그것이 답이다. 터널이면 서비스 순서대로
    "활성이고 IPv4 주소가 있는" 첫 물리 인터페이스를 쓴다.
    """
    if default4_iface and not is_tunnel(default4_iface):
        return default4_iface

    known = {p["dev"] for p in ports}

    def usable(dev: str) -> bool:
        if dev not in known or is_tunnel(dev) or dev.startswith(SKIP_PREFIXES):
            return False
        st = if_state.get(dev) or {}
        return bool(st.get("inet")) and st.get("status") != "inactive"

    for dev in order:
        if usable(dev):
            return dev
    for p in ports:
        if usable(p["dev"]):
            return p["dev"]
    return None


def candidate_states(ports: List[Dict[str, str]],
                     if_state: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """주 인터페이스가 없을 때 후보 물리 인터페이스들의 상태.

    **없을 때야말로 이 상태가 필요하다.** 예전에는 primary 가 None 이면 if_state 를
    통째로 버려서, "무선이 끊겨 있었나" 와 "붙어 있었는데 IPv4 주소만 없었나" 를
    나중에 가를 수가 없었다 (2026-09-20 맥북, 판정 없는 주기 56건).
    주소·MAC 은 남기지 않는다. 상태만으로 그 구분이 된다.
    """
    out: List[Dict[str, Any]] = []
    for p in ports:
        dev = p["dev"]
        if dev.startswith(SKIP_PREFIXES) or is_tunnel(dev):
            continue
        st = if_state.get(dev) or {}
        out.append({
            "kind": p.get("kind"),
            "status": st.get("status"),
            "flags_up": bool(st.get("flags_up")),
            "has_inet": bool(st.get("inet")),
            "has_inet6": bool(st.get("inet6")),
        })
    return out


def probe() -> Capability:
    r = run(["route", "-n", "get", "default"], timeout=4)
    detail = "기본 경로 조회 가능" if r.rc == 0 else "기본 경로 없음(오프라인일 수 있음)"
    return Capability(NAME, OK, detail, provides=["primary", "default4", "default6", "addrs"])


def collect(ctx: Dict[str, Any] = None) -> Dict[str, Any]:
    ports = parse_hardware_ports(run(["networksetup", "-listallhardwareports"], timeout=8).out)
    order = parse_service_order(run(["networksetup", "-listnetworkserviceorder"], timeout=8).out)

    if_state: Dict[str, Dict[str, Any]] = {}
    for p in ports:
        dev = p["dev"]
        if dev.startswith(SKIP_PREFIXES):
            continue
        r = run(["ifconfig", dev], timeout=4)
        if r.rc == 0:
            if_state[dev] = parse_ifconfig(r.out)

    d4 = parse_route_get(run(["route", "-n", "get", "default"], timeout=4).out)
    d6 = parse_route_get(run(["route", "-n", "get", "-inet6", "default"], timeout=4).out)

    primary = choose_primary(ports, order, if_state, d4.get("interface"))
    kind = next((p["kind"] for p in ports if p["dev"] == primary), "unknown")

    tunnel_iface = d4.get("interface") if d4.get("interface") and is_tunnel(d4["interface"]) else None

    scoped = {}
    if primary:
        scoped = parse_route_get(run(["route", "-n", "get", "-ifscope", primary, "default"], timeout=4).out)

    st = if_state.get(primary or "", {})
    # **주 인터페이스가 없을 때야말로 후보들의 상태가 필요하다.** 예전에는
    # primary 가 None 이면 여기서 if_state 를 통째로 버려서, "무선이 끊겨
    # 있었나" 와 "붙어 있었는데 IPv4 주소만 없었나" 를 나중에 가를 수가 없었다
    # (2026-09-20 맥북, 판정 없는 주기 56건). 주소는 남기지 않고 상태만 남긴다.
    candidates = candidate_states(ports, if_state) if primary is None else None
    return {
        "ports": ports,
        "primary": primary,
        "primary_kind": kind,
        "candidates": candidates,
        "primary_status": st.get("status"),
        "primary_mac": ident("mac", st["ether"]) if st.get("ether") else None,
        "primary_inet": [ident("ipv4", a["addr"]) for a in st.get("inet", [])],
        "primary_netmask": (st.get("inet") or [{}])[0].get("netmask"),
        "primary_inet6": [ident("ipv6", a["addr"]) for a in st.get("inet6", [])],
        "default4_iface": d4.get("interface"),
        "default4_gateway": ident("ipv4", d4["gateway"]) if d4.get("gateway") else None,
        "default6_iface": d6.get("interface"),
        "default6_gateway": ident("ipv6", d6["gateway"]) if d6.get("gateway") else None,
        "scoped_gateway": ident("ipv4", scoped["gateway"]) if scoped.get("gateway") else None,
        "tunnel_iface": tunnel_iface,
    }
