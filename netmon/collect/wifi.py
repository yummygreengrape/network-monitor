"""Wi-Fi 연결 정보.

SSID·BSSID 는 위치 서비스 권한이 있어야 읽힌다. 권한이 없으면 macOS 가
값을 `<redacted>` 로 바꿔 준다 — 오류가 아니라 가려진 것이므로 그렇게 보고한다.

`Security`(암호화 방식)는 권한 없이도 읽힌다. 그래서 암호화 다운그레이드
탐지는 권한과 무관하게 동작하고, evil twin(BSSID) 탐지만 권한을 요구한다.
동의하지 않았으면 SSID·BSSID 를 아예 기록하지 않는다.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from ..model import ident
from ..util import OK, UNSUPPORTED, NEEDS_CONSENT, Capability, run
from .dhcp import parse_getsummary

NAME = "wifi"

REDACTED = "<redacted>"


def parse_wifi_summary(text: str) -> Dict[str, Optional[str]]:
    """`ipconfig getsummary <dev>` 에서 Wi-Fi 관련 키만."""
    flat = parse_getsummary(text)
    return {
        "ssid": flat.get("SSID"),
        "bssid": flat.get("BSSID"),
        "security": flat.get("Security"),
        "network_id": flat.get("NetworkID"),
        "link_active": flat.get("LinkStatusActive"),
    }


def is_redacted(value: Optional[str]) -> bool:
    return value is not None and "redacted" in value.lower()


def location_state(parsed: Dict[str, Optional[str]]) -> str:
    """위치 권한 상태를 관측으로 판정한다.

    granted  SSID 값이 실제로 보인다
    denied   SSID 키는 있는데 <redacted> 다
    unknown  SSID 키 자체가 없다 (Wi-Fi 미연결이거나 이 버전엔 키가 없다)
    """
    ssid = parsed.get("ssid")
    if ssid is None:
        return "unknown"
    return "denied" if is_redacted(ssid) else "granted"


def probe(ctx: Dict[str, Any] = None) -> Capability:
    ctx = ctx or {}
    if ctx.get("primary_kind") != "wifi":
        return Capability(NAME, UNSUPPORTED,
                          "주 인터페이스가 Wi-Fi 가 아님 (%s)" % ctx.get("primary_kind"),
                          hint="유선 전용 기종이거나 지금 유선으로 붙어 있다")
    dev = ctx.get("primary")
    parsed = parse_wifi_summary(run(["ipconfig", "getsummary", dev], timeout=5).out)
    loc = location_state(parsed)
    if loc == "granted":
        return Capability(NAME, OK, "SSID·BSSID 읽힘", provides=["ssid", "bssid", "security"])
    if loc == "denied":
        return Capability(
            NAME, NEEDS_CONSENT,
            "SSID·BSSID 가 <redacted> — 위치 서비스 권한 없음",
            provides=["security"],
            hint="암호화 방식 변화 탐지는 그대로 동작한다. evil twin(BSSID) 탐지만 권한이 필요하다.",
        )
    return Capability(NAME, UNSUPPORTED, "Wi-Fi 연결 정보 없음 (미연결?)", provides=["security"])


def collect(ctx: Dict[str, Any] = None) -> Dict[str, Any]:
    ctx = ctx or {}
    if ctx.get("primary_kind") != "wifi":
        return {"applicable": False, "reason": "주 인터페이스가 Wi-Fi 가 아님"}

    dev = ctx.get("primary")
    parsed = parse_wifi_summary(run(["ipconfig", "getsummary", dev], timeout=5).out)
    loc = location_state(parsed)

    out: Dict[str, Any] = {
        "applicable": True,
        "security": parsed.get("security"),
        "link_active": parsed.get("link_active"),
        "location": loc,
    }

    # 동의하지 않았으면 SSID·BSSID 를 기록하지 않는다. 권한이 우연히
    # 열려 있어도 마찬가지다 — 필요 조건 이상은 쓰지 않는다.
    if ctx.get("allow_location") and loc == "granted":
        out["ssid"] = ident("ssid", parsed["ssid"])
        out["bssid"] = ident("bssid", parsed["bssid"]) if parsed.get("bssid") else None
    else:
        out["ssid"] = None
        out["bssid"] = None
        out["identity_withheld"] = not ctx.get("allow_location")
    return out
