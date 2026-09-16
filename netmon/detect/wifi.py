"""Wi-Fi 판정 — 암호화 다운그레이드, BSSID 변경(evil twin 후보).

암호화 방식은 위치 권한 없이 읽히므로 다운그레이드 탐지는 항상 동작한다.
BSSID 탐지는 위치 권한과 사용자 동의가 둘 다 있을 때만 동작한다.
"""
from __future__ import annotations

import re
from typing import List, Optional

from ..model import (CONFIRMED, HIGH, LOW, MEDIUM, QUALITY, SECURITY, SUSPECT,
                     Finding, Observation, unwrap)

FEATURE = "detect.wifi"

# 세대별 기본 점수. 낮을수록 약하다.
# macOS 가 돌려주는 문자열은 한 가지가 아니다. 실측에서 `NONE` 과 `WPA2_PSK` 를
# 봤고, `WPA2 Personal`, `WPA2/WPA3 Personal` 같은 형태도 쓰인다. 고정 문자열
# 표를 쓰면 처음 보는 표기에서 조용히 판정 불가가 되므로 토큰으로 읽는다.
GENERATION = {"wpa": 2, "wpa2": 3, "wpa3": 5}
ENTERPRISE_BONUS = 1


def rank(security: Optional[str]) -> Optional[int]:
    """암호화 강도. 모르는 표기면 None — 모르면서 약해졌다고 단정하지 않는다."""
    if not security:
        return None
    key = re.sub(r"[^a-z0-9]", "", security.lower())
    if not key or key in ("none", "open", "unknown"):
        return 0 if key in ("none", "open") else None
    if "wep" in key:
        return 1

    # wpa3 가 wpa 를 포함하므로 긴 것부터 떼어 낸다
    rest = key
    found = []
    for gen in ("wpa3", "wpa2"):
        if gen in rest:
            found.append(gen)
            rest = rest.replace(gen, "")
    if "wpa" in rest:
        found.append("wpa")
    if not found:
        return None

    # 혼합 모드(WPA2/WPA3)는 약한 쪽 접속을 허용하므로 약한 쪽으로 친다
    base = min(GENERATION[g] for g in found)
    if "enterprise" in key or "eap" in key:
        base += ENTERPRISE_BONUS
    return base


def detect(prev: Optional[Observation], cur: Observation, ctx) -> List[Finding]:
    out: List[Finding] = []
    if prev is None or not cur.get("wifi", "applicable"):
        return out

    p_sec = prev.get("wifi", "security")
    c_sec = cur.get("wifi", "security")

    # --- 암호화 방식 변화 ---
    if p_sec and c_sec and p_sec != c_sec:
        p_rank, c_rank = rank(p_sec), rank(c_sec)
        downgrade = p_rank is not None and c_rank is not None and c_rank < p_rank
        attribution = ctx.identity_attribution()
        out.append(Finding(
            axis=SECURITY,
            kind="WIFI_SECURITY_DOWNGRADE" if downgrade else "WIFI_SECURITY_CHANGED",
            confidence=CONFIRMED,
            severity=HIGH if downgrade and not attribution else MEDIUM,
            summary=("Wi-Fi 암호화가 약해졌습니다 (%s → %s). 같은 이름을 쓰는 약한 접속점으로 유인됐을 수 있습니다."
                     % (p_sec, c_sec)) if downgrade else
                    ("Wi-Fi 암호화 방식이 바뀌었습니다 (%s → %s)." % (p_sec, c_sec)),
            evidence={"prev": p_sec, "cur": c_sec, "known_ranks": [p_rank, c_rank],
                      "source": "ipconfig getsummary"},
            attribution=attribution,
        ))

    # --- BSSID 변경 ---
    # 동의하지 않았으면 수집기가 값을 기록하지 않으므로 여기서 자동으로 건너뛴다.
    p_bss, c_bss = unwrap(prev.get("wifi", "bssid")), unwrap(cur.get("wifi", "bssid"))
    p_ssid, c_ssid = unwrap(prev.get("wifi", "ssid")), unwrap(cur.get("wifi", "ssid"))
    if p_bss and c_bss and p_bss != c_bss:
        same_name = bool(p_ssid) and p_ssid == c_ssid
        if same_name and ctx.enabled("detect.evil_twin"):
            # 같은 이름, 다른 AP. 정상 로밍이 압도적으로 흔하다.
            # 게이트웨이 MAC 이나 DHCP 서버까지 같이 바뀌었으면 의심을 올린다.
            gw_changed = unwrap(prev.get("arp", "gateway_mac")) != unwrap(cur.get("arp", "gateway_mac"))
            srv_changed = unwrap(prev.get("dhcp", "server_identifier")) != unwrap(cur.get("dhcp", "server_identifier"))
            corroborated = gw_changed or srv_changed
            out.append(Finding(
                axis=SECURITY, kind="EVIL_TWIN_CANDIDATE" if corroborated else "WIFI_ROAM",
                confidence=SUSPECT if corroborated else CONFIRMED,
                severity=HIGH if corroborated else "info",
                summary=("같은 SSID 인데 접속점과 게이트웨이·DHCP 가 함께 바뀌었습니다. "
                         "정상적인 로밍에서는 보통 게이트웨이가 그대로입니다."
                         if corroborated else
                         "같은 SSID 안에서 접속점이 바뀌었습니다 (로밍)."),
                evidence={"prev_bssid": prev.get("wifi", "bssid"), "bssid": cur.get("wifi", "bssid"),
                          "gateway_mac_changed": gw_changed, "dhcp_server_changed": srv_changed,
                          "source": "ipconfig getsummary"},
                attribution=None if corroborated else ctx.identity_attribution(),
            ))
        elif not same_name:
            out.append(Finding(
                axis=QUALITY, kind="WIFI_NETWORK_SWITCHED",
                confidence=CONFIRMED, severity="info",
                summary="다른 Wi-Fi 네트워크로 옮겼습니다.",
                evidence={"prev_ssid": prev.get("wifi", "ssid"), "ssid": cur.get("wifi", "ssid"),
                          "source": "ipconfig getsummary"},
                attribution=ctx.identity_attribution(),
            ))

    # --- 링크 끊김 ---
    p_link, c_link = prev.get("wifi", "link_active"), cur.get("wifi", "link_active")
    if p_link and c_link and p_link != c_link:
        out.append(Finding(
            axis=QUALITY, kind="WIFI_LINK_CHANGED",
            confidence=CONFIRMED, severity=LOW,
            summary="Wi-Fi 링크 상태가 바뀌었습니다 (%s → %s)." % (p_link, c_link),
            evidence={"prev": p_link, "cur": c_link, "source": "ipconfig getsummary"},
            attribution=ctx.quality_attribution(),
        ))

    return out
