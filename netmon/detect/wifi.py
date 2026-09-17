"""Wi-Fi 판정 — 암호화 다운그레이드, BSSID 변경(evil twin 후보).

암호화 방식은 위치 권한 없이 읽히므로 다운그레이드 탐지는 항상 동작한다.
BSSID 탐지는 위치 권한과 사용자 동의가 둘 다 있을 때만 동작한다.
"""
from __future__ import annotations

import re
from typing import List, Optional

from .. import messages as msg
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


def _band_value(band) -> float:
    try:
        return float(band)
    except (TypeError, ValueError):
        return 0.0


def detect(prev: Optional[Observation], cur: Observation, ctx) -> List[Finding]:
    out: List[Finding] = []
    if prev is None or not cur.get("wifi", "applicable"):
        return out

    p_sec = prev.get("wifi", "security")
    c_sec = cur.get("wifi", "security")
    p_bss, c_bss = unwrap(prev.get("wifi", "bssid")), unwrap(cur.get("wifi", "bssid"))
    p_ssid, c_ssid = unwrap(prev.get("wifi", "ssid")), unwrap(cur.get("wifi", "ssid"))
    # 이름을 둘 다 읽었을 때만 같다/다르다를 말할 수 있다. 하나라도 모르면 None.
    same_name = (p_ssid == c_ssid) if (p_ssid and c_ssid) else None

    # --- 암호화 방식 변화 ---
    if p_sec and c_sec and p_sec != c_sec:
        p_rank, c_rank = rank(p_sec), rank(c_sec)
        downgrade = p_rank is not None and c_rank is not None and c_rank < p_rank
        attribution = ctx.identity_attribution()
        if not downgrade:
            template = msg.WIFI_SECURITY_CHANGED
        elif same_name is True:
            # 같은 이름, 약해진 암호화. 유인의 형태가 바로 이것이다.
            template = msg.WIFI_SECURITY_DOWNGRADE
        elif same_name is False:
            # 이름이 다르면 "같은 이름으로 유인" 은 사실이 아니다.
            template = msg.WIFI_SECURITY_DOWNGRADE_OTHER
        else:
            template = msg.WIFI_SECURITY_DOWNGRADE_UNKNOWN
        out.append(Finding(
            axis=SECURITY,
            kind="WIFI_SECURITY_DOWNGRADE" if downgrade else "WIFI_SECURITY_CHANGED",
            confidence=CONFIRMED,
            severity=HIGH if downgrade and not attribution else MEDIUM,
            summary=template % (p_sec, c_sec),
            evidence={"prev": p_sec, "cur": c_sec, "known_ranks": [p_rank, c_rank],
                      "same_ssid": same_name,
                      "source": "ipconfig getsummary"},
            attribution=attribution,
        ))

    # --- BSSID 변경 ---
    # 동의하지 않았으면 수집기가 값을 기록하지 않으므로 여기서 자동으로 건너뛴다.
    # 밴드 전환은 로밍이 아니다. 같은 공유기의 다른 라디오로 옮긴 것이고,
    # 속도 상한이 통째로 달라진다. 실측에서 5GHz→2.4GHz 전환이 "로밍" 으로만
    # 기록돼, 상한이 1200→144 Mbps 로 떨어진 채 몇 시간이 지났다.
    p_band, c_band = prev.get("wifi", "band"), cur.get("wifi", "band")
    band_changed = bool(p_band and c_band and p_band != c_band)
    if band_changed:
        p_rate, c_rate = prev.get("wifi", "txrate"), cur.get("wifi", "txrate")
        downward = _band_value(c_band) < _band_value(p_band)
        if isinstance(p_rate, int) and isinstance(c_rate, int):
            summary = msg.WIFI_BAND_CHANGED_RATE % (p_band, c_band, p_rate, c_rate)
        else:
            summary = msg.WIFI_BAND_CHANGED % (p_band, c_band)
        out.append(Finding(
            axis=QUALITY, kind="WIFI_BAND_CHANGED",
            confidence=CONFIRMED,
            severity=MEDIUM if downward else "info",
            summary=summary,
            evidence={"prev_band": p_band, "band": c_band,
                      "prev_channel": prev.get("wifi", "channel"),
                      "channel": cur.get("wifi", "channel"),
                      "prev_txrate": p_rate, "txrate": c_rate,
                      "source": "CoreWLAN"},
            attribution=ctx.identity_attribution(),
        ))

    if p_bss and c_bss and p_bss != c_bss:
        if same_name is True and ctx.enabled("detect.evil_twin"):
            # 같은 이름, 다른 AP. 정상 로밍이 압도적으로 흔하다.
            # 게이트웨이 MAC 이나 DHCP 서버까지 같이 바뀌었으면 의심을 올린다.
            gw_changed = unwrap(prev.get("arp", "gateway_mac")) != unwrap(cur.get("arp", "gateway_mac"))
            srv_changed = unwrap(prev.get("dhcp", "server_identifier")) != unwrap(cur.get("dhcp", "server_identifier"))
            corroborated = gw_changed or srv_changed
            # 같은 이름·다른 BSSID 지만 밴드가 바뀐 것이면 위에서 이미 알렸다.
            # 로밍으로 중복 보고하지 않는다. 다만 게이트웨이·DHCP 까지 바뀐
            # 경우(corroborated)는 밴드와 무관하게 그대로 올린다.
            if corroborated or not band_changed:
                out.append(Finding(
                    axis=SECURITY, kind="EVIL_TWIN_CANDIDATE" if corroborated else "WIFI_ROAM",
                    confidence=SUSPECT if corroborated else CONFIRMED,
                    severity=HIGH if corroborated else "info",
                    summary=(msg.EVIL_TWIN_CANDIDATE if corroborated else msg.WIFI_ROAM),
                    evidence={"prev_bssid": prev.get("wifi", "bssid"), "bssid": cur.get("wifi", "bssid"),
                              "gateway_mac_changed": gw_changed, "dhcp_server_changed": srv_changed,
                              "source": "ipconfig getsummary"},
                    attribution=None if corroborated else ctx.identity_attribution(),
                ))
        elif same_name is False or same_name is None:
            # 이름을 못 읽었으면 로밍인지 이동인지 가릴 수 없다. 이동이라고
            # 단정하지 않고 접속점이 바뀐 사실만 적는다.
            out.append(Finding(
                axis=QUALITY,
                kind="WIFI_NETWORK_SWITCHED" if same_name is False else "WIFI_AP_CHANGED",
                confidence=CONFIRMED, severity="info",
                summary=(msg.WIFI_NETWORK_SWITCHED if same_name is False
                         else msg.WIFI_AP_CHANGED_NAME_UNKNOWN),
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
            summary=msg.WIFI_LINK_CHANGED % (p_link, c_link),
            evidence={"prev": p_link, "cur": c_link, "source": "ipconfig getsummary"},
            attribution=ctx.quality_attribution(),
        ))

    return out
