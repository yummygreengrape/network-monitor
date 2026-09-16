"""외부 명령 실행과 가용성 탐침.

여기서만 subprocess 를 쓴다. 판정 로직은 이 모듈을 import 하지 않는다 —
그래야 판정을 네트워크 없이 테스트할 수 있다.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional, Sequence

DEFAULT_TIMEOUT = 5.0


@dataclass
class CmdResult:
    """명령 하나의 실행 결과.

    rc 만으로 성공을 판정하지 않는다. macOS 명령 중에는 권한이 없을 때
    usage 를 출력하고 rc=0 으로 끝나는 것(`wdutil info`)과, 정상적인 빈 상태를
    rc=1 로 알리는 것(`security dump-trust-settings`)이 모두 있다.
    """

    argv: Sequence[str]
    rc: int
    out: str
    err: str
    timed_out: bool = False
    not_found: bool = False

    @property
    def ok(self) -> bool:
        return self.rc == 0 and not self.timed_out and not self.not_found


def run(argv: Sequence[str], timeout: float = DEFAULT_TIMEOUT, stdin: str = "") -> CmdResult:
    """명령을 실행한다. 예외를 던지지 않고 항상 CmdResult 를 돌려준다."""
    try:
        p = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            input=stdin,
        )
    except FileNotFoundError:
        return CmdResult(argv, 127, "", "명령을 찾을 수 없음", not_found=True)
    except PermissionError as e:
        return CmdResult(argv, 126, "", str(e))
    except subprocess.TimeoutExpired:
        return CmdResult(argv, -1, "", "제한 시간 초과", timed_out=True)
    return CmdResult(argv, p.returncode, p.stdout or "", p.stderr or "")


# launchd 는 PATH 로 /usr/bin:/bin:/usr/sbin:/sbin 만 준다. 사용자가 설치한
# 도구는 대부분 여기 있다. PATH 에만 기대면 상시 실행에서 VPN 감시가 조용히
# 아무것도 못 본다 — 실제로 그렇게 됐다.
EXTRA_TOOL_DIRS = (
    "/usr/local/bin",
    "/opt/homebrew/bin",
    "/opt/local/bin",
    "/Applications/Tailscale.app/Contents/MacOS",
)


def find_tool(cmd: str) -> Optional[str]:
    """명령의 절대 경로. PATH 에 없으면 흔한 설치 위치도 찾아본다."""
    found = shutil.which(cmd)
    if found:
        return found
    for d in EXTRA_TOOL_DIRS:
        cand = os.path.join(d, cmd)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def have(cmd: str) -> bool:
    return find_tool(cmd) is not None


# 탐침 상태. "왜 못 쓰는지"를 반드시 남긴다 — 남의 맥에서 탐지가 조용히
# 빠지는 것이 이 도구의 가장 위험한 실패 방식이다.
OK = "ok"                 # 지금 쓸 수 있다
UNSUPPORTED = "unsupported"   # 이 맥/이 macOS 버전에 없다 (Wi-Fi 없는 기종 등)
NEEDS_CONSENT = "needs-consent"  # 사용자 동의가 필요하다 (위치 권한, 외부 요청)
NEEDS_SUDO = "needs-sudo"     # 관리자 권한이 필요하다
BROKEN = "broken"         # 있어야 하는데 기대와 다르게 동작한다


@dataclass
class Capability:
    """수집기 하나가 이 기계에서 쓸 수 있는지."""

    name: str
    status: str
    detail: str = ""
    provides: List[str] = field(default_factory=list)
    hint: str = ""

    @property
    def usable(self) -> bool:
        return self.status == OK

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "provides": list(self.provides),
            "hint": self.hint,
        }


def first_line(text: str, default: str = "") -> str:
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line
    return default


def parse_kv_block(text: str, sep: str = ":") -> dict:
    """`key: value` 줄을 dict 로. 같은 키가 여러 번이면 마지막 값이 남는다."""
    out = {}
    for line in text.splitlines():
        if sep not in line:
            continue
        k, _, v = line.partition(sep)
        k = k.strip()
        if k:
            out[k] = v.strip()
    return out


def ts_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def monotonic() -> float:
    import time

    return time.monotonic()


def wall() -> float:
    import time

    return time.time()


def coalesce(*values: Optional[str]) -> Optional[str]:
    for v in values:
        if v:
            return v
    return None


def is_loopback(addr: Optional[str]) -> bool:
    """루프백 주소인가. 수집과 판정 양쪽이 쓴다."""
    import ipaddress

    if not addr:
        return False
    try:
        return ipaddress.ip_address(str(addr).split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def normalize_mask(mask: Optional[str]) -> Optional[str]:
    """넷마스크를 점 표기로. ifconfig 는 0xffffff00, DHCP 는 255.255.255.0 을 준다."""
    if not mask:
        return None
    m = mask.strip()
    if m.lower().startswith("0x"):
        try:
            n = int(m, 16)
        except ValueError:
            return None
        return ".".join(str((n >> s) & 0xFF) for s in (24, 16, 8, 0))
    return m


def subnet_of(addr: Optional[str], mask: Optional[str]) -> Optional[str]:
    """주소와 넷마스크로 서브넷 문자열. 실패하면 None."""
    import ipaddress

    mask = normalize_mask(mask)
    if not addr or not mask:
        return None
    try:
        return str(ipaddress.ip_network("%s/%s" % (addr, mask), strict=False))
    except ValueError:
        return None
